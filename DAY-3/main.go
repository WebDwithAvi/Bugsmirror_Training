package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

const apktoolVersion = "2.6.0"

func decompileAPK(apkFilePath, outputDir string, wg *sync.WaitGroup, resultChan chan<- *APKInfo) {
	defer wg.Done()

	apkInfo := &APKInfo{
		ApkInfo: ApkDetails{
			FileName: filepath.Base(apkFilePath),
		},
		Decompilation: DecompilationInfo{
			Status:          ProcessResult(Pass),
			OutputDirectory: outputDir,
			LayoutChecksums: make(map[string]string),
		},
	}

	// Download Apktool JAR from an alternative mirror
	err := downloadFile(fmt.Sprintf("https://github.com/iBotPeaches/Apktool/releases/download/v%s/apktool_%s.jar", apktoolVersion, apktoolVersion), "apktool.jar")
	if err != nil {
		logError("Error downloading Apktool JAR for %s: %v", apkInfo.ApkInfo.FileName, err)
		apkInfo.Result = Fail
		resultChan <- apkInfo
		return
	} else {
		apkInfo.Decompilation.Status = ProcessResult(Pass)
	}

	// Perform the APK decompilation
	cmd := exec.Command("java", "-jar", "apktool.jar", "d", apkFilePath, "-o", outputDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		if strings.Contains(err.Error(), "zip file is empty") {
			log.Printf("Empty or corrupt APK file for %s. Check if the APK is valid.\n", apkInfo.ApkInfo.FileName)
		}
		logError("Error during APK decompilation for %s: %v", apkInfo.ApkInfo.FileName, err)
		apkInfo.Decompilation.Status = Fail
		resultChan <- apkInfo
		return
	} else {
		apkInfo.Decompilation.Status = ProcessResult(Pass)
		log.Printf("APK decompilation completed for %s.\n", apkInfo.ApkInfo.FileName)
	}

	// Extract the package name
	manifestPath := outputDir + "/AndroidManifest.xml"
	cmd = exec.Command("xmlstarlet", "sel", "-T", "-t", "-v", "/manifest/@package", manifestPath)

	output, err := cmd.Output()
	if err != nil {
		logError("Error extracting package name for %s: %v", apkInfo.ApkInfo.FileName, err)
		apkInfo.Result = Fail
		resultChan <- apkInfo
		return
	}

	apkInfo.ApkInfo.PackageName = string(output)

	// Calculate checksum for AndroidManifest.xml
	manifestChecksum, err := calculateChecksum(outputDir + "/AndroidManifest.xml")
	if err != nil {
		logError("Error calculating checksum for AndroidManifest.xml for %s: %v", apkInfo.ApkInfo.FileName, err)
		apkInfo.Result = Fail
		resultChan <- apkInfo
		return
	} else {
		apkInfo.ApkInfo.ManifestChecksum = manifestChecksum
	}

	// Calculate checksum for all files under res/layout
	layoutDir := outputDir + "/res/layout"
	err = filepath.Walk(layoutDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			layoutChecksum, err := calculateChecksum(path)
			if err != nil {
				log.Printf("Error calculating checksum for %s in %s: %v\n", info.Name(), apkInfo.ApkInfo.FileName, err)
				return nil
			}
			relativePath, _ := filepath.Rel(outputDir, path)
			apkInfo.Decompilation.LayoutChecksums[relativePath] = layoutChecksum
		}
		return nil
	})
	if err != nil {
		logError("Error calculating checksums for res/layout for %s: %v", apkInfo.ApkInfo.FileName, err)
		apkInfo.Result = Fail
		resultChan <- apkInfo
		return
	}

	resultChan <- apkInfo
}

func main() {
	var wg sync.WaitGroup
	resultChan := make(chan *APKInfo)

	// List of APK files
	apkFiles := []string{
		"com.anumati.apk",
		"com.goibibo.apk",
		"com.julian.fastracing.apk",
		"com.nekki.shadowfight.apk",
		"com.nekki.shadowfight (1).apk",
	}

	for _, apkFile := range apkFiles {
		// Create output directory based on APK file name
		outputDir := fmt.Sprintf("output_%s", apkFile)

		// Increment the WaitGroup counter.
		wg.Add(1)

		// Process the APK in a goroutine
		go decompileAPK(apkFile, outputDir, &wg, resultChan)
	}

	// Close the result channel when all goroutines are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results from the channel
	for result := range resultChan {
		// Print or store the result as needed
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			logError("Error marshaling JSON for %s: %v", result.ApkInfo.FileName, err)
			continue
		}

		jsonFilePath := fmt.Sprintf("%s_result.json", result.ApkInfo.FileName)
		err = os.WriteFile(jsonFilePath, jsonData, 0644)
		if err != nil {
			logError("Error writing JSON file for %s: %v", result.ApkInfo.FileName, err)
			continue
		}

		log.Printf("Result JSON file created for %s: %s\n", result.ApkInfo.FileName, jsonFilePath)
	}
}
