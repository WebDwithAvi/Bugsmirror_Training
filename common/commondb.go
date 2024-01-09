package common

import "sync"

type User struct {
	ID         string
	SecretCode string
	Name       string
	Email      string
	Playlists  map[string]Playlist
}

// Playlist represents a playlist's data.
type Playlist struct {
	ID    string
	Songs map[string]Song
}

// Song represents a song's data.
type Song struct {
	ID        string
	Name      string
	Composers string
	MusicURL  string
}

var (
	Users      = make(map[string]User)
	UsersLock  sync.Mutex
	IdCounter  = 1
	PlaylistID = 1
	SongID     = 1
)
var RequestBody struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	SecretCode string `json:"secretCode"`
}
