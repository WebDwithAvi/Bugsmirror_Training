package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

type ProcessResult string

const (
	Pass ProcessResult = "Pass"
	Fail ProcessResult = "Fail"
)

type APKInfo struct {
	Result        ProcessResult     `json:"result"`
	ApkInfo       ApkDetails        `json:"apkInfo"`
	Decompilation DecompilationInfo `json:"decompilation"`
}

type ApkDetails struct {
	PackageName      string `json:"packageName"`
	DownloadLink     string `json:"downloadLink"`
	FileName         string `json:"fileName"`
	ManifestChecksum string `json:"manifestChecksum"`
}

type DecompilationInfo struct {
	Status          ProcessResult     `json:"status"`
	OutputDirectory string            `json:"outputDirectory"`
	LayoutChecksums map[string]string `json:"checksums"`
}

func downloadFile(url, outputPath string) error {
	response, err := http.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return logError("HTTP response error: %s", response.Status)
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return logError("Error creating file %s: %v", outputPath, err)
	}
	defer outputFile.Close()

	_, err = io.Copy(outputFile, response.Body)
	if err != nil {
		return logError("Error copying content to file %s: %v", outputPath, err)
	}

	return nil
}

func calculateChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func logError(format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	log.Println(msg)
	return fmt.Errorf(msg)
}
