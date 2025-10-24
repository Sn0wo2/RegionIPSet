package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	apnicURL  = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"
	outputDir = "ipsets"

	ipv4Type = "ipv4"
	ipv6Type = "ipv6"
)

type IPRecord struct {
	Registry string
	Region   string
	Type     string
	StartIP  string
	Value    uint64
	Date     string
	Status   string
}

func main() {
	if err := cleanupOutputDir(); err != nil {
		panic(err)
	}

	data, err := downloadAPNICData()
	if err != nil {
		panic(err)
	}

	records, err := parseAPNICData(data)
	if err != nil {
		panic(err)
	}

	sort.Slice(records, func(i, j int) bool {
		isIUnknown := strings.EqualFold(records[i].Region, "unknown")
		isJUnknown := strings.EqualFold(records[j].Region, "unknown")

		if isIUnknown {
			return false
		}

		if isJUnknown {
			return true
		}

		return records[i].Region < records[j].Region
	})

	generateIPSets(records)

	fmt.Printf("Success generate ipset to %s\n", outputDir)
}

func cleanupOutputDir() error {
	if err := os.RemoveAll(outputDir); err != nil {
		return err
	}

	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return err
	}

	fmt.Printf("Cleanup path: %s\n", outputDir)

	return nil
}

func downloadAPNICData() (string, error) {
	resp, err := http.Get(apnicURL)
	if err != nil {
		return "", err
	}

	defer func() {
		_ = resp.Body.Close() // #nosec errcheck
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status code: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func parseAPNICData(data string) ([]IPRecord, error) {
	var records []IPRecord

	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, "|")
		if len(fields) < 7 {
			continue
		}

		for i, f := range fields {
			if f == "" {
				fmt.Printf("LINE [%s] INDEX %d FIELD EMPTY!\n", line, i)
				fields[i] = "UNKNOWN"

				break
			}
		}

		record := IPRecord{
			Registry: fields[0],
			Region:   fields[1],
			Type:     fields[2],
			StartIP:  fields[3],
			Date:     fields[5],
			Status:   fields[6],
		}

		if value, err := strconv.ParseUint(fields[4], 10, 64); err == nil {
			record.Value = value
		}

		if record.Type == ipv4Type || record.Type == ipv6Type {
			records = append(records, record)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

func generateIPSets(records []IPRecord) {
	regionMap := make(map[string][]IPRecord)
	for _, record := range records {
		regionMap[record.Region] = append(regionMap[record.Region], record)
	}

	regions := make([]string, 0, len(regionMap))
	for r := range regionMap {
		regions = append(regions, r)
	}

	sort.Slice(regions, func(i, j int) bool {
		isIUnknown := strings.EqualFold(regions[i], "unknown")
		isJUnknown := strings.EqualFold(regions[j], "unknown")

		if isIUnknown {
			return false
		}

		if isJUnknown {
			return true
		}

		return regions[i] < regions[j]
	})

	for _, region := range regions {
		regionRecords := regionMap[region]

		ipv4Filename := filepath.Join(outputDir, strings.ToLower(region)+"_v4.ipset")
		if created, err := generateIPSetFile(ipv4Filename, ipv4Type, regionRecords); err != nil {
			panic(err)
		} else if created {
			fmt.Printf("%s\n", ipv4Filename)
		}

		ipv6Filename := filepath.Join(outputDir, strings.ToLower(region)+"_v6.ipset")
		if created, err := generateIPSetFile(ipv6Filename, ipv6Type, regionRecords); err != nil {
			panic(err)
		} else if created {
			fmt.Printf("%s\n", ipv6Filename)
		}
	}

	generateSummary(records)
}

func generateIPSetFile(filename, ipType string, records []IPRecord) (bool, error) {
	var lines []string

	for _, record := range records {
		if record.Type == ipType {
			cidr, err := ipToCIDR(record.StartIP, record.Value, ipType)
			if err == nil {
				lines = append(lines, cidr)
			}
		}
	}

	if len(lines) == 0 {
		return false, nil
	}

	file, err := os.Create(filename) // #nosec G304
	if err != nil {
		panic(err)
	}

	defer func() {
		_ = file.Close() // #nosec errcheck
	}()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			panic(err)
		}
	}

	if err := writer.Flush(); err != nil {
		panic(err)
	}

	return true, nil
}

func ipToCIDR(startIP string, count uint64, ipType string) (string, error) {
	if count == 0 {
		return "", errors.New("empty IP")
	}

	var maskBits int
	if ipType == ipv4Type {
		maskBits = 32 - log2(count)
		if maskBits < 0 || maskBits > 32 {
			return "", fmt.Errorf("bad ipv4 mask: %d", maskBits)
		}
	} else {
		maskBits = 128 - log2(count)
		if maskBits < 0 || maskBits > 128 {
			return "", fmt.Errorf("bad ipv6 mask: %d", maskBits)
		}
	}

	return fmt.Sprintf("%s/%d", startIP, maskBits), nil
}

func log2(n uint64) int {
	if n == 0 {
		return 0
	}

	bits := 0

	for n > 1 {
		n >>= 1
		bits++
	}

	return bits
}

func generateSummary(records []IPRecord) {
	summaryFile := filepath.Join(filepath.Join(outputDir, "../"), "README.md")

	file, err := os.Create(summaryFile) // #nosec G304
	if err != nil {
		panic(err)
	}

	defer func() {
		_ = file.Close() // #nosec errcheck
	}()

	writer := bufio.NewWriter(file)

	defer func() {
		_ = writer.Flush() // #nosec errcheck
	}()

	regionStats := make(map[string]struct {
		ipv4 int
		ipv6 int
	})

	for _, record := range records {
		stats := regionStats[record.Region]
		switch record.Type {
		case ipv4Type:
			stats.ipv4++
		case ipv6Type:
			stats.ipv6++
		}

		regionStats[record.Region] = stats
	}

	regions := make([]string, 0, len(regionStats))
	for region := range regionStats {
		regions = append(regions, region)
	}

	sort.Slice(regions, func(i, j int) bool {
		isIUnknown := strings.EqualFold(regions[i], "unknown")
		isJUnknown := strings.EqualFold(regions[j], "unknown")

		if isIUnknown {
			return false
		}

		if isJUnknown {
			return true
		}

		return regions[i] < regions[j]
	})

	if _, err := writer.WriteString("# APNIC IP\n\n"); err != nil {
		panic(err)
	}

	if _, err := fmt.Fprintf(writer, "Generate at: %s (UTC+8)\n\n", time.Now().In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05")); err != nil {
		panic(err)
	}

	if _, err := writer.WriteString("| Country/Region | IPv4 | IPv6 | Total |\n"); err != nil {
		panic(err)
	}

	if _, err := writer.WriteString("|----------------|------|------|-------|\n"); err != nil {
		panic(err)
	}

	totalIPv4, totalIPv6 := 0, 0

	for _, region := range regions {
		stats := regionStats[region]

		total := stats.ipv4 + stats.ipv6
		if _, err := fmt.Fprintf(writer, "| %s | %d | %d | %d |\n",
			region, stats.ipv4, stats.ipv6, total); err != nil {
			panic(err)
		}

		totalIPv4 += stats.ipv4
		totalIPv6 += stats.ipv6
	}

	if _, err := fmt.Fprintf(writer, "| **Total** | **%d** | **%d** | **%d** |\n",
		totalIPv4, totalIPv6, totalIPv4+totalIPv6); err != nil {
		panic(err)
	}

	if _, err := writer.WriteString("\n## Files\n\n"); err != nil {
		panic(err)
	}

	files, _ := filepath.Glob(filepath.Join(outputDir, "*.ipset"))
	sort.Slice(files, func(i, j int) bool {
		isIUnknown := strings.Contains(files[i], "unknown")
		isJUnknown := strings.Contains(files[j], "unknown")

		if isIUnknown {
			return false
		}

		if isJUnknown {
			return true
		}

		return files[i] < files[j]
	})

	if _, err := writer.WriteString("```\n"); err != nil {
		panic(err)
	}

	for _, file := range files {
		if _, err := writer.WriteString(filepath.Base(file) + "\n"); err != nil {
			panic(err)
		}
	}

	if _, err := writer.WriteString("```"); err != nil {
		panic(err)
	}
}
