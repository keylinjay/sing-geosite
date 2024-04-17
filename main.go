package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sagernet/sing-box/common/geosite"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/google/go-github/v45/github"
	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

var githubClient *github.Client // 定义一个githubClient变量，类型为*github.Client

func init() { // 初始化函数
	accessToken, loaded := os.LookupEnv("ACCESS_TOKEN") // 从环境变量中查找ACCESS_TOKEN，并赋值给accessToken变量
	if !loaded { // 如果环境变量ACCESS_TOKEN不存在
		githubClient = github.NewClient(nil) // 使用nil创建一个新的githubClient
		return
	}
	transport := &github.BasicAuthTransport{ // 创建一个BasicAuthTransport
		Username: accessToken, // 将accessToken赋值给Username
	}
	githubClient = github.NewClient(transport.Client()) // 使用transport.Client()创建一个新的githubClient
}

// This function fetches the latest release of a repository from a given URL
func fetch(from string) (*github.RepositoryRelease, error) {
	// Split the URL by the "/" character and store the first two elements in the "names" array
	names := strings.SplitN(from, "/", 2)
	// Get the latest release of the repository using the GitHub API
	latestRelease, _, err := githubClient.Repositories.GetLatestRelease(context.Background(), names[0], names[1])
	// If an error occurs, return nil and the error
	if err != nil {
		return nil, err
	}
	// Return the latest release and no error
	return latestRelease, err
}

// Function to download a file from a given URL
func get(downloadURL *string) ([]byte, error) {
	// Log the URL being downloaded
	log.Info("download ", *downloadURL)
	// Get the response from the URL
	response, err := http.Get(*downloadURL)
	if err != nil {
		// Return an error if the response was not received
		return nil, err
	}
	// Close the response body
	defer response.Body.Close()
	// Read all the data from the response body and return it
	return io.ReadAll(response.Body)
}

// download function downloads the geosite.dat file from the given release
func download(release *github.RepositoryRelease) ([]byte, error) {
	// Find the geosite.dat asset in the release assets
	geositeAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "geosite.dat"
	})
	// Find the geosite.dat.sha256sum asset in the release assets
	geositeChecksumAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "geosite.dat.sha256sum"
	})
	// If geosite.dat asset is not found, return an error
	if geositeAsset == nil {
		return nil, E.New("geosite asset not found in upstream release ", release.Name)
	}
	// If geosite.dat.sha256sum asset is not found, return an error
	if geositeChecksumAsset == nil {
		return nil, E.New("geosite asset not found in upstream release ", release.Name)
	}
	// Download the geosite.dat file
	data, err := get(geositeAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	// Download the geosite.dat.sha256sum file
	remoteChecksum, err := get(geositeChecksumAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	// Calculate the checksum of the geosite.dat file
	checksum := sha256.Sum256(data)
	// If the calculated checksum does not match the remote checksum, return an error
	if hex.EncodeToString(checksum[:]) != string(remoteChecksum[:64]) {
		return nil, E.New("checksum mismatch")
	}
	// Return the downloaded data
	return data, nil
}

func parse(vGeositeData []byte) (map[string][]geosite.Item, error) {
	vGeositeList := routercommon.GeoSiteList{}
	err := proto.Unmarshal(vGeositeData, &vGeositeList)
	if err != nil {
		return nil, err
	}
	domainMap := make(map[string][]geosite.Item)
	for _, vGeositeEntry := range vGeositeList.Entry {
		code := strings.ToLower(vGeositeEntry.CountryCode)
		domains := make([]geosite.Item, 0, len(vGeositeEntry.Domain)*2)
		attributes := make(map[string][]*routercommon.Domain)
		for _, domain := range vGeositeEntry.Domain {
			if len(domain.Attribute) > 0 {
				for _, attribute := range domain.Attribute {
					attributes[attribute.Key] = append(attributes[attribute.Key], domain)
				}
			}
			switch domain.Type {
			case routercommon.Domain_Plain:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainKeyword,
					Value: domain.Value,
				})
			case routercommon.Domain_Regex:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainRegex,
					Value: domain.Value,
				})
			case routercommon.Domain_RootDomain:
				if strings.Contains(domain.Value, ".") {
					domains = append(domains, geosite.Item{
						Type:  geosite.RuleTypeDomain,
						Value: domain.Value,
					})
				}
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainSuffix,
					Value: "." + domain.Value,
				})
			case routercommon.Domain_Full:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomain,
					Value: domain.Value,
				})
			}
		}
		domainMap[code] = common.Uniq(domains)
		for attribute, attributeEntries := range attributes {
			attributeDomains := make([]geosite.Item, 0, len(attributeEntries)*2)
			for _, domain := range attributeEntries {
				switch domain.Type {
				case routercommon.Domain_Plain:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainKeyword,
						Value: domain.Value,
					})
				case routercommon.Domain_Regex:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainRegex,
						Value: domain.Value,
					})
				case routercommon.Domain_RootDomain:
					if strings.Contains(domain.Value, ".") {
						attributeDomains = append(attributeDomains, geosite.Item{
							Type:  geosite.RuleTypeDomain,
							Value: domain.Value,
						})
					}
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainSuffix,
						Value: "." + domain.Value,
					})
				case routercommon.Domain_Full:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomain,
						Value: domain.Value,
					})
				}
			}
			domainMap[code+"@"+attribute] = common.Uniq(attributeDomains)
		}
	}
	return domainMap, nil
}

type filteredCodePair struct {
	code    string
	badCode string
}

func filterTags(data map[string][]geosite.Item) {
	var codeList []string
	for code := range data {
		codeList = append(codeList, code)
	}
	var badCodeList []filteredCodePair
	var filteredCodeMap []string
	var mergedCodeMap []string
	for _, code := range codeList {
		codeParts := strings.Split(code, "@")
		if len(codeParts) != 2 {
			continue
		}
		leftParts := strings.Split(codeParts[0], "-")
		var lastName string
		if len(leftParts) > 1 {
			lastName = leftParts[len(leftParts)-1]
		}
		if lastName == "" {
			lastName = codeParts[0]
		}
		if lastName == codeParts[1] {
			delete(data, code)
			filteredCodeMap = append(filteredCodeMap, code)
			continue
		}
		if "!"+lastName == codeParts[1] {
			badCodeList = append(badCodeList, filteredCodePair{
				code:    codeParts[0],
				badCode: code,
			})
		} else if lastName == "!"+codeParts[1] {
			badCodeList = append(badCodeList, filteredCodePair{
				code:    codeParts[0],
				badCode: code,
			})
		}
	}
	for _, it := range badCodeList {
		badList := data[it.badCode]
		if badList == nil {
			panic("bad list not found: " + it.badCode)
		}
		delete(data, it.badCode)
		newMap := make(map[geosite.Item]bool)
		for _, item := range data[it.code] {
			newMap[item] = true
		}
		for _, item := range badList {
			delete(newMap, item)
		}
		newList := make([]geosite.Item, 0, len(newMap))
		for item := range newMap {
			newList = append(newList, item)
		}
		data[it.code] = newList
		mergedCodeMap = append(mergedCodeMap, it.badCode)
	}
	sort.Strings(filteredCodeMap)
	sort.Strings(mergedCodeMap)
	os.Stderr.WriteString("filtered " + strings.Join(filteredCodeMap, ",") + "\n")
	os.Stderr.WriteString("merged " + strings.Join(mergedCodeMap, ",") + "\n")
}

func mergeTags(data map[string][]geosite.Item) {
	var codeList []string
	for code := range data {
		codeList = append(codeList, code)
	}
	var cnCodeList []string
	for _, code := range codeList {
		codeParts := strings.Split(code, "@")
		if len(codeParts) != 2 {
			continue
		}
		if codeParts[1] != "cn" {
			continue
		}
		if !strings.HasPrefix(codeParts[0], "category-") {
			continue
		}
		if strings.HasSuffix(codeParts[0], "-cn") || strings.HasSuffix(codeParts[0], "-!cn") {
			continue
		}
		cnCodeList = append(cnCodeList, code)
	}
	newMap := make(map[geosite.Item]bool)
	for _, item := range data["geolocation-cn"] {
		newMap[item] = true
	}
	for _, code := range cnCodeList {
		for _, item := range data[code] {
			newMap[item] = true
		}
	}
	newList := make([]geosite.Item, 0, len(newMap))
	for item := range newMap {
		newList = append(newList, item)
	}
	data["geolocation-cn"] = newList
	println("merged cn categories: " + strings.Join(cnCodeList, ","))
}

func generate(release *github.RepositoryRelease, output string, cnOutput string, ruleSetOutput string) error {
	vData, err := download(release)
	if err != nil {
		return err
	}
	domainMap, err := parse(vData)
	if err != nil {
		return err
	}
	filterTags(domainMap)
	mergeTags(domainMap)
	

	outputPath, _ := filepath.Abs(output)
	os.Stderr.WriteString("write " + outputPath + "\n")
	outputFile, err := os.Create(output)
	if err != nil {
		return err
	}
	defer outputFile.Close()
	err = geosite.Write(outputFile, domainMap)
	if err != nil {
		return err
	}
	cnCodes := []string{
		"geolocation-cn",
	}
	cnDomainMap := make(map[string][]geosite.Item)
	for _, cnCode := range cnCodes {
		cnDomainMap[cnCode] = domainMap[cnCode]
	}
	cnOutputFile, err := os.Create(cnOutput)
	if err != nil {
		return err
	}
	defer cnOutputFile.Close()
	err = geosite.Write(cnOutputFile, cnDomainMap)
	if err != nil {
		return err
	}
	os.RemoveAll(ruleSetOutput)
	err = os.MkdirAll(ruleSetOutput, 0o755)
	if err != nil {
		return err
	}
	for code, domains := range domainMap {
		var headlessRule option.DefaultHeadlessRule
		defaultRule := geosite.Compile(domains)
		headlessRule.Domain = defaultRule.Domain
		headlessRule.DomainSuffix = defaultRule.DomainSuffix
		headlessRule.DomainKeyword = defaultRule.DomainKeyword
		headlessRule.DomainRegex = defaultRule.DomainRegex
		var plainRuleSet option.PlainRuleSet
		plainRuleSet.Rules = []option.HeadlessRule{
			{
				Type:           C.RuleTypeDefault,
				DefaultOptions: headlessRule,
			},
		}
		srsPath, _ := filepath.Abs(filepath.Join(ruleSetOutput, "geosite-"+code+".srs"))
		//os.Stderr.WriteString("write " + srsPath + "\n")
		outputRuleSet, err := os.Create(srsPath)
		if err != nil {
			return err
		}
		err = srs.Write(outputRuleSet, plainRuleSet)
		if err != nil {
			outputRuleSet.Close()
			return err
		}
		outputRuleSet.Close()
	}
	return nil
}

func setActionOutput(name string, content string) {
	os.Stdout.WriteString("::set-output name=" + name + "::" + content + "\n")
}

func release(source string, destination string, output string, cnOutput string, ruleSetOutput string) error {
	sourceRelease, err := fetch(source)
	if err != nil {
		return err
	}
	destinationRelease, err := fetch(destination)
	if err != nil {
		log.Warn("missing destination latest release")
	} else {
		if os.Getenv("NO_SKIP") != "true" && strings.Contains(*destinationRelease.Name, *sourceRelease.Name) {
			log.Info("already latest")
			setActionOutput("skip", "true")
			return nil
		}
	}
	err = generate(sourceRelease, output, cnOutput, ruleSetOutput)
	if err != nil {
		return err
	}
	// 将*sourceRelease.Name中的空格换成-
	
	setActionOutput("tag", strings.ReplaceAll(*sourceRelease.Name, " ", "-"))
	return nil
}

func main() {
	err := release(
		"Loyalsoldier/v2ray-rules-dat",
		"keylinjay/sing-geosite",
		"geosite.db",
		"geosite-cn.db",
		"rule-set",
	)
	if err != nil {
		log.Fatal(err)
	}
}
