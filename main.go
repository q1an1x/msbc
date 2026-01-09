package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type BaseOutbound struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}

type TrojanOutbound struct {
	BaseOutbound

	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Password   string `json:"password"`
	TLS        struct {
		Enabled    bool   `json:"enabled"`
		ServerName string `json:"server_name,omitempty"`
		Insecure   bool   `json:"insecure"`
	} `json:"tls"`
}

type SelectorOutbound struct {
	BaseOutbound

	Outbounds []string `json:"outbounds"`
}

type GroupOutbound struct {
	SelectorOutbound

	InterruptExistConnections bool `json:"interrupt_exist_connections"`
}

type SelectorsConfig struct {
	Outbounds []json.RawMessage `json:"outbounds"`
}

func outboundKey(server string, port int) string {
	return server + ":" + strconv.Itoa(port)
}

func parseTrojanURL(raw string) (*TrojanOutbound, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}

	if u.Scheme != "trojan" {
		log.Printf("Unsupported scheme: %s", u.Scheme)
		return nil, nil
	}

	password := u.User.Username()
	host := u.Hostname()

	portStr := u.Port()
	if portStr == "" {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	allowInsecure := q.Get("allowInsecure") == "1"
	sni := q.Get("sni")

	rawTag := u.Fragment
	rawTag = strings.TrimSpace(rawTag)
	tag := strings.TrimSpace(removeEmoji(rawTag))

	ob := &TrojanOutbound{
		BaseOutbound: BaseOutbound{
			Type: "trojan",
			Tag:  tag,
		},
		Server:     host,
		ServerPort: port,
		Password:   password,
	}

	ob.TLS.Enabled = true
	ob.TLS.ServerName = sni
	ob.TLS.Insecure = allowInsecure

	return ob, nil
}

func extractRegion(tag string) string {
	fields := strings.Fields(tag)
	if len(fields) <= 1 {
		return tag
	}
	return strings.Join(fields[:len(fields)-1], " ")
}

type ServersConfig struct {
	Outbounds []TrojanOutbound `json:"outbounds"`
}

type GroupsConfig struct {
	Outbounds []GroupOutbound `json:"outbounds"`
}

func main() {
	srvListURL := os.Getenv("SERVER_LIST_URL")

	if srvListURL == "" {
		log.Fatal("$SERVER_LIST_URL environment variable not set")
	}

	log.Printf("fetching from %s", srvListURL)
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := client.Get(srvListURL)
	if err != nil {
		log.Fatal(err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("unexpected HTTP status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("fetched %d bytes", len(body))

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		log.Fatalf("base64 decode failed: %v", err)
	}

	lines := strings.Split(string(decoded), "\n")
	log.Printf("decoded %d lines", len(lines))

	outbounds := make([]TrojanOutbound, 0)
	indexMap := make(map[string]int)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		ob, err := parseTrojanURL(line)
		if err != nil {
			log.Printf("skipping invalid line: %v", err)
			continue
		}
		if ob == nil {
			continue
		}

		key := outboundKey(ob.Server, ob.ServerPort)

		if idx, exists := indexMap[key]; exists {
			outbounds[idx] = *ob
		} else {
			indexMap[key] = len(outbounds)
			outbounds = append(outbounds, *ob)
		}
	}

	log.Printf("parsed %d unique servers", len(outbounds))

	regionTags := make(map[string][]string)
	regionIndex := make(map[string]int)
	regionOrder := make([]string, 0)

	for _, ob := range outbounds {
		region := extractRegion(ob.Tag)

		if _, exists := regionIndex[region]; !exists {
			regionIndex[region] = len(regionOrder)
			regionOrder = append(regionOrder, region)
		}

		regionTags[region] = append(regionTags[region], ob.Tag)
	}

	for region, tags := range regionTags {
		if len(tags) == 1 {
			originalTag := tags[0]

			for i := range outbounds {
				if outbounds[i].Tag == originalTag {
					outbounds[i].Tag = region
					break
				}
			}

			regionTags[region][0] = region
		}
	}

	cfg := ServersConfig{
		Outbounds: outbounds,
	}

	jsonBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	err = os.MkdirAll("config", 0755)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile("config/servers.json", jsonBytes, 0644)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("wrote config/servers.json")

	var groupOutbounds []GroupOutbound

	for _, region := range regionOrder {
		tags := regionTags[region]

		if len(tags) <= 1 {
			continue
		}

		autoTag := region + "-auto"

		urltest := GroupOutbound{
			SelectorOutbound: SelectorOutbound{
				BaseOutbound: BaseOutbound{
					Type: "urltest",
					Tag:  autoTag,
				},
				Outbounds: tags,
			},
			InterruptExistConnections: false,
		}

		selector := GroupOutbound{
			SelectorOutbound: SelectorOutbound{
				BaseOutbound: BaseOutbound{
					Type: "selector",
					Tag:  region,
				},
				Outbounds: append([]string{autoTag}, tags...),
			},
			InterruptExistConnections: true,
		}

		groupOutbounds = append(groupOutbounds, urltest, selector)
	}

	log.Printf("parsed %d server groups", len(groupOutbounds))

	groupsCfg := GroupsConfig{
		Outbounds: groupOutbounds,
	}

	groupsJSON, err := json.MarshalIndent(groupsCfg, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile("config/groups.json", groupsJSON, 0644)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("wrote config/groups.json")

	selectors, err := loadSelectors("config/selectors.scheme.json")
	if err != nil {
		log.Fatal(err)
	}

	for i, ob := range selectors {
		sel, ok := ob.(SelectorOutbound)
		if !ok {
			continue
		}

		sel.Outbounds = appendUnique(sel.Outbounds, regionOrder)
		selectors[i] = sel
	}

	selectorsCfg := struct {
		Outbounds []any `json:"outbounds"`
	}{
		Outbounds: selectors,
	}

	data, err := json.MarshalIndent(selectorsCfg, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile("config/selectors.json", data, 0644)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("wrote config/selectors.json")

	err = exportConfig("config", "/etc/sing-box")
	if err != nil {
		log.Fatalf("failed to export configs: %v", err)
	}

	log.Printf("all done")
}

func removeEmoji(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.So, r) {
			return -1
		}
		return r
	}, s)
}

func loadSelectors(path string) ([]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var cfg SelectorsConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	var result []any

	for _, raw := range cfg.Outbounds {
		var base struct {
			Type string `json:"type"`
		}

		if err := json.Unmarshal(raw, &base); err != nil {
			return nil, err
		}

		if base.Type != "selector" {
			result = append(result, raw)
			continue
		}

		var sel SelectorOutbound
		if err := json.Unmarshal(raw, &sel); err != nil {
			return nil, err
		}

		result = append(result, sel)
	}

	return result, nil
}

func appendUnique(dst []string, src []string) []string {
	seen := make(map[string]struct{}, len(dst))
	for _, v := range dst {
		seen[v] = struct{}{}
	}

	for _, v := range src {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		dst = append(dst, v)
	}

	return dst
}

func exportConfig(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if strings.HasSuffix(name, ".scheme.json") {
			continue
		}

		srcPath := filepath.Join(srcDir, name)
		dstPath := filepath.Join(dstDir, name)

		srcFile, err := os.Open(srcPath)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		dstFile, err := os.Create(dstPath)
		if err != nil {
			return err
		}
		defer dstFile.Close()

		_, err = io.Copy(dstFile, srcFile)
		if err != nil {
			return err
		}

		log.Printf("exported %s -> %s", srcPath, dstPath)
	}

	return nil
}
