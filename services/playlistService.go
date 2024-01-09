package services

import (
	"Training/common"
	"Training/models"
	"encoding/json"
	"net/http"
	"sync"
)

// userlogin.go

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, common.False, http.StatusMethodNotAllowed)
		return
	}

	// Parsing from the request body
	if err := json.NewDecoder(r.Body).Decode(&common.RequestBody); err != nil {
		http.Error(w, common.False, http.StatusBadRequest)
		return
	}

	// Validate email format
	if !common.IsValidEmail(common.RequestBody.Email) {
		http.Error(w, common.False, http.StatusBadRequest)
		return
	}

	// Validate password
	if common.IsValidPassword(common.RequestBody.Password) {
		http.Error(w, common.False, http.StatusBadRequest)
		return
	}

	// Additional check for non-empty email and password
	if common.RequestBody.Email == "" || common.RequestBody.Password == "" {
		http.Error(w, common.False, http.StatusBadRequest)
		return
	}

	models.UsersLock.Lock()
	defer models.UsersLock.Unlock()

	var foundUser *models.User // Assuming User is the type of elements in models.Users
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Concurrent search using goroutines
	for _, user := range models.Users {
		wg.Add(1)
		go func(u models.User) {
			defer wg.Done()
			if u.SecretCode == common.RequestBody.SecretCode && u.Email == common.RequestBody.Email && u.Password == common.RequestBody.Password {
				mu.Lock()
				foundUser = &u
				mu.Unlock()
			}
		}(user)
	}

	wg.Wait()

	if foundUser != nil {
		common.EncodeToJSON(w, *foundUser)
		return
	}

	http.Error(w, common.Message, http.StatusNotFound)
}

func Register(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, common.False, http.StatusMethodNotAllowed)
		return
	}
	// parsing the request body
	var reqBody struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, common.Message, http.StatusBadRequest)
		return
	}

	models.UsersLock.Lock()
	defer models.UsersLock.Unlock()

	// Generate a unique secret code
	secretCode := common.GenerateSecretKey() // after registration this function generates a unique secret key for the user
	user := models.User{
		ID:         common.GenerateUniqueID(),
		SecretCode: secretCode,
		Name:       reqBody.Name,
		Email:      reqBody.Email,
	}

	models.Users[user.ID] = user
	common.EncodeToJSON(w, user)
}

func ViewProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	//destructing from request body
	var reqBody struct {
		UserID string `json:"userID"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, userExists := models.Users[reqBody.UserID]
	if !userExists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	common.EncodeToJSON(w, user)
}

func AddSongs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	//destructing from request body
	var reqBody struct {
		UserID     string      `json:"userID"`
		PlaylistID string      `json:"playlistID"`
		Song       models.Song `json:"song"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	models.UsersLock.Lock()
	defer models.UsersLock.Unlock()

	user, userExists := models.Users[reqBody.UserID]
	if !userExists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	playlist, playlistExists := user.Playlists[reqBody.PlaylistID]
	if !playlistExists {
		http.Error(w, "Playlist not found", http.StatusNotFound)
		return
	}

	// here the logic to find user and playlist by the ID
	//var user *models.User
	//var playlist *models.Playlist

	//for i := range users {
	//	for j := range users[i].Playlists {
	//		if users[i].Playlists[j].ID == reqBody.PlaylistID {
	//			user = &users[i]
	//			playlist = &users[i].Playlists[j]
	//			break
	//		}
	//	}
	//}
	//TODO: Generateplaylistid will come below
	reqBody.Song.ID = common.GenerateSongID()
	playlist.Songs[reqBody.Song.ID] = reqBody.Song

	// this function adds the song to the existing playlist
	//reqBody.Song.ID = generateUniqueID()
	//playlist.Songs = append(playlist.Songs, reqBody.Song)

	common.EncodeToJSON(w, playlist)

}

func GetAllSongs(w http.ResponseWriter, r *http.Request) {

}
func CreatePlaylist(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	var reqBody struct {
		UserID string `json:"userID"`
		//PlaylistID string      `json:"playlistID"`
		Playlist models.Playlist `json:"playlist"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	models.UsersLock.Lock()
	defer models.UsersLock.Unlock()

	user, userExists := models.Users[reqBody.UserID]
	if !userExists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	reqBody.Playlist.ID = common.GeneratePlaylistID()
	user.Playlists[reqBody.Playlist.ID] = reqBody.Playlist
	common.EncodeToJSON(w, user.Playlists)
}

func DeleteSongs(w http.ResponseWriter, r *http.Request) {

}

func DeletePlaylist(w http.ResponseWriter, r *http.Request) {

}

func SongDetails(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	//destructing from request body
	var reqBody struct {
		UserID     string `json:"userID"`
		PlaylistID string `json:"playlistID"`
		SongID     string `json:"SongID"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	//models.UsersLock.Lock()
	//defer models.UsersLock.Unlock()

	user, userExists := models.Users[reqBody.UserID]
	if !userExists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	playlist, playlistExists := user.Playlists[reqBody.PlaylistID]
	if !playlistExists {
		http.Error(w, "Playlist not found", http.StatusNotFound)
		return
	}
	song, songExists := playlist.Songs[reqBody.SongID]
	if !songExists {
		http.Error(w, "Song not found", http.StatusNotFound)
		return
	}
	common.EncodeToJSON(w, song)
}
