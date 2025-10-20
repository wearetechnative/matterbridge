package bmsteams

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/42wim/matterbridge/bridge"
	"github.com/42wim/matterbridge/bridge/config"
	"github.com/davecgh/go-spew/spew"

	"github.com/mattn/godown"
	msgraph "github.com/yaegashi/msgraph.go/beta"
	"github.com/yaegashi/msgraph.go/msauth"

	"golang.org/x/oauth2"
)

var (
	// offline_access is included to allow refresh tokens for long-running services
	defaultScopes = []string{"openid", "profile", "offline_access", "Group.Read.All", "Group.ReadWrite.All"}
	attachRE      = regexp.MustCompile(`<attachment id=.*?attachment>`)
)

type Bmsteams struct {
	gc    *msgraph.GraphServiceRequestBuilder
	ctx   context.Context
	botID string
	*bridge.Config
}

func New(cfg *bridge.Config) bridge.Bridger {
	return &Bmsteams{Config: cfg}
}

// logger is a minimal interface to log errors/warnings without importing a specific logger type
type logger interface {
	Errorf(string, ...interface{})
	Warnf(string, ...interface{})
}

// savingTokenSource wraps a base TokenSource and persists the token cache
// to disk whenever the refresh token rotates.
type savingTokenSource struct {
	base  oauth2.TokenSource
	m     *msauth.Manager
	path  string
	log   logger
	mu    sync.Mutex
	lastRT string
}

func (s *savingTokenSource) Token() (*oauth2.Token, error) {
	tok, err := s.base.Token()
	if err != nil {
		return nil, err
	}

	// If refresh token rotated, save the cache to disk so restarts continue working
	s.mu.Lock()
	defer s.mu.Unlock()
	if tok.RefreshToken != "" && tok.RefreshToken != s.lastRT {
		if err := s.m.SaveFile(s.path); err != nil {
			if s.log != nil {
				s.log.Errorf("Couldn't save sessionfile in %s: %v", s.path, err)
			}
		} else {
			s.lastRT = tok.RefreshToken
		}
	}

	return tok, nil
}

func (b *Bmsteams) Connect() error {
	tokenCachePath := b.GetString("sessionFile")
	if tokenCachePath == "" {
		tokenCachePath = "msteams_session.json"
	}
	ctx := context.Background()
	m := msauth.NewManager()
	m.LoadFile(tokenCachePath) //nolint:errcheck

	// Request device code flow with offline_access so we get refresh tokens
	ts, err := m.DeviceAuthorizationGrant(ctx, b.GetString("TenantID"), b.GetString("ClientID"), defaultScopes, nil)
	if err != nil {
		return err
	}

	// Save the initial token cache (contains refresh token)
	if err := m.SaveFile(tokenCachePath); err != nil {
		b.Log.Errorf("Couldn't save sessionfile in %s: %s", tokenCachePath, err)
	}
	// Make file readable only for matterbridge user
	if err := os.Chmod(tokenCachePath, 0o600); err != nil {
		b.Log.Errorf("Couldn't change permissions for %s: %s", tokenCachePath, err)
	}

	// Wrap the TokenSource so any refresh writes the new refresh token to disk
	savingTS := &savingTokenSource{
		base:   oauth2.ReuseTokenSource(nil, ts),
		m:      m,
		path:   tokenCachePath,
		log:    b.Log,
		lastRT: "", // will be set after first save on rotation
	}

	httpClient := oauth2.NewClient(ctx, savingTS)
	graphClient := msgraph.NewClient(httpClient)
	b.gc = graphClient
	b.ctx = ctx

	if err := b.setBotID(); err != nil {
		return err
	}
	b.Log.Info("Connection succeeded")
	return nil
}

func (b *Bmsteams) Disconnect() error {
	return nil
}

func (b *Bmsteams) JoinChannel(channel config.ChannelInfo) error {
	go func(name string) {
		for {
			err := b.poll(name)
			if err != nil {
				b.Log.Errorf("polling failed for %s: %s. retrying in 5 seconds", name, err)
			}
			time.Sleep(time.Second * 5)
		}
	}(channel.Name)
	return nil
}

func (b *Bmsteams) Send(msg config.Message) (string, error) {
	b.Log.Debugf("=> Receiving %#v", msg)
	if msg.ParentValid() {
		return b.sendReply(msg)
	}

	// Handle prefix hint for unthreaded messages.
	if msg.ParentNotFound() {
		msg.ParentID = ""
		msg.Text = fmt.Sprintf("[thread]: %s", msg.Text)
	}

	ct := b.gc.Teams().ID(b.GetString("TeamID")).Channels().ID(msg.Channel).Messages().Request()
	text := msg.Username + msg.Text
	content := &msgraph.ItemBody{Content: &text}
	rmsg := &msgraph.ChatMessage{Body: content}
	res, err := ct.Add(b.ctx, rmsg)
	if err != nil {
		return "", err
	}
	return *res.ID, nil
}

func (b *Bmsteams) sendReply(msg config.Message) (string, error) {
	ct := b.gc.Teams().ID(b.GetString("TeamID")).Channels().ID(msg.Channel).Messages().ID(msg.ParentID).Replies().Request()
	// Handle prefix hint for unthreaded messages.

	text := msg.Username + msg.Text
	content := &msgraph.ItemBody{Content: &text}
	rmsg := &msgraph.ChatMessage{Body: content}
	res, err := ct.Add(b.ctx, rmsg)
	if err != nil {
		return "", err
	}
	return *res.ID, nil
}

func (b *Bmsteams) getReplies(channel string, msg msgraph.ChatMessage) ([]msgraph.ChatMessage, error) {
	ct := b.gc.Teams().ID(b.GetString("TeamID")).Channels().ID(channel).Messages().ID(*msg.ID).Replies().Request()
	rct, err := ct.Get(b.ctx)
	if err != nil {
		return nil, err
	}
	b.Log.Debugf("got %#v replies", len(rct))
	return rct, nil
}

func (b *Bmsteams) getMessages(channel string) ([]msgraph.ChatMessage, error) {
	ct := b.gc.Teams().ID(b.GetString("TeamID")).Channels().ID(channel).Messages().Request()
	rct, err := ct.Get(b.ctx)
	if err != nil {
		return nil, err
	}
	b.Log.Debugf("got %#v messages", len(rct))
	for _, msg := range rct {
		replyct, replyerr := b.getReplies(channel, msg)
		if replyerr != nil {
			return nil, replyerr
		}
		rct = append(rct, replyct...)
	}
	return rct, nil
}

//nolint:gocognit
func (b *Bmsteams) poll(channelName string) error {
	msgmap := make(map[string]time.Time)
	b.Log.Debug("getting initial messages")
	res, err := b.getMessages(channelName)
	if err != nil {
		return err
	}
	for _, msg := range res {
		msgmap[*msg.ID] = *msg.CreatedDateTime
		if msg.LastModifiedDateTime != nil {
			msgmap[*msg.ID] = *msg.LastModifiedDateTime
		}
	}
	time.Sleep(time.Second * 5)
	b.Log.Debug("polling for messages")
	for {
		res, err := b.getMessages(channelName)
		if err != nil {
			return err
		}
		for i := len(res) - 1; i >= 0; i-- {
			msg := res[i]
			if mtime, ok := msgmap[*msg.ID]; ok {
				if mtime == *msg.CreatedDateTime && msg.LastModifiedDateTime == nil {
					continue
				}
				if msg.LastModifiedDateTime != nil && mtime == *msg.LastModifiedDateTime {
					continue
				}
			}

			if b.GetBool("debug") {
				b.Log.Debug("Msg dump: ", spew.Sdump(msg))
			}

			// skip non-user message for now.
			if msg.From == nil || msg.From.User == nil {
				continue
			}

			if *msg.From.User.ID == b.botID {
				b.Log.Debug("skipping own message")
				msgmap[*msg.ID] = *msg.CreatedDateTime
				continue
			}

			msgmap[*msg.ID] = *msg.CreatedDateTime
			if msg.LastModifiedDateTime != nil {
				msgmap[*msg.ID] = *msg.LastModifiedDateTime
			}
			b.Log.Debugf("<= Sending message from %s on %s to gateway", *msg.From.User.DisplayName, b.Account)
			text := b.convertToMD(*msg.Body.Content)
			rmsg := config.Message{
				Username: *msg.From.User.DisplayName,
				Text:     text,
				Channel:  channelName,
				Account:  b.Account,
				Avatar:   "",
				UserID:   *msg.From.User.ID,
				ID:       *msg.ID,
				Extra:    make(map[string][]interface{}),
			}
			if msg.ReplyToID != nil {
				rmsg.ParentID = *msg.ReplyToID
			}

			b.handleAttachments(&rmsg, msg)
			b.Log.Debugf("<= Message is %#v", rmsg)
			b.Remote <- rmsg
		}
		time.Sleep(time.Second * 60)
	}
}

func (b *Bmsteams) setBotID() error {
	req := b.gc.Me().Request()
	r, err := req.Get(b.ctx)
	if err != nil {
		return err
	}
	b.botID = *r.ID
	return nil
}

func (b *Bmsteams) convertToMD(text string) string {
	if !strings.Contains(text, "<div>") {
		return text
	}
	var sb strings.Builder
	err := godown.Convert(&sb, strings.NewReader(text), nil)
	if err != nil {
		b.Log.Errorf("Couldn't convert message to markdown %s", text)
		return text
	}
	return sb.String()
}
