package main

import (
	"Training/services"
	"net/http"
)

func main() {

	http.HandleFunc("/login", services.Login)
	http.HandleFunc("/register", services.Register)
	http.HandleFunc("/viewProfile", services.ViewProfile)
	http.HandleFunc("/getAllSongsOfPlaylist", services.GetAllSongs)
	http.HandleFunc("/createPlaylist", services.CreatePlaylist)
	http.HandleFunc("/addSongtoPlaylist", services.AddSongs)
	http.HandleFunc("/deleteSongsfromplaylist", services.DeleteSongs)
	http.HandleFunc("/deletePlaylist", services.DeletePlaylist)
	http.HandleFunc("/getSongDetail", services.SongDetails)
	err := http.ListenAndServe(":4000", nil)
	if err != nil {
		return
	}

}
