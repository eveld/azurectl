package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path"
	"strings"

	"github.com/codegangsta/cli"
	"github.com/pkg/browser"
)

//
// Token is the received JWT token.
//
type Token struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    string `json:"expires_in"`
	Scope        string `json:"scope"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

//
// Credentials contains information to authenticate and do requests.
//
type Credentials struct {
	Company string
	Token   Token
}

//
// Group represents an Active Directory group.
//
type Group struct {
	DisplayName     string `json:"displayName"`
	MailNickname    string `json:"mailNickname"`
	MailEnabled     bool   `json:"mailEnabled"`
	SecurityEnabled bool   `json:"securityEnabled"`
	Description     string `json:"description"`
}

func main() {
	app := cli.NewApp()
	app.Name = "azurectl"
	app.Version = Version
	app.Usage = ""
	app.Author = "Erik Veld"
	app.HideHelp = true
	app.Commands = Commands
	app.Run(os.Args)
}

//
// Commands that can be invoked on Azure Control
//
var Commands = []cli.Command{
	{
		Name:        "auth",
		Usage:       "Authenticate with Azure Active Directory",
		Description: "",
		Action:      authenticate,
		ArgsUsage:   "<company> <id> <secret>",
	},
	{
		Name:        "group",
		Usage:       "Group commands",
		Description: "",
		Subcommands: []cli.Command{
			{
				Name:        "list",
				Usage:       "List groups",
				Description: "",
				Action:      listGroups,
			},
			{
				Name:        "get",
				Usage:       "Get details of a group",
				Description: "",
				Action:      getGroup,
				ArgsUsage:   "<id>",
			},
			{
				Name:        "create",
				Usage:       "Create a group",
				Description: "",
				Action:      createGroup,
				ArgsUsage:   "<name>",
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:  "description, d",
						Usage: "Description of the group",
					},
				},
			},
			{
				Name:        "delete",
				Usage:       "Delete a group",
				Description: "",
				Action:      deleteGroup,
				ArgsUsage:   "<id>",
			},
		},
	},
}

//
// Authenticate the user and request an access token.
//
func authenticate(c *cli.Context) {
	if len(c.Args()) != 3 {
		cli.ShowCommandHelp(c, "auth")
		os.Exit(1)
	}

	company := c.Args()[0]
	clientID := c.Args()[1]
	clientSecret := c.Args()[2]

	showAuthPage(clientID)
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		getAuthCode(w, r, company, clientID, clientSecret)
	})
	http.ListenAndServe(":27015", nil)
}

//
// Show the browser and direct the user to the login page.
//
func showAuthPage(clientID string) {
	address := fmt.Sprintf("https://login.windows.net/common/oauth2/authorize?redirect_uri=http://localhost:27015/auth&client_id=%s&response_type=code&resource=https://graph.windows.net", clientID)
	browser.OpenURL(address)
}

//
// Capture the response from the browser and get the authorization code.
//
func getAuthCode(w http.ResponseWriter, r *http.Request, company string, clientID string, clientSecret string) {
	params, err := url.ParseQuery(r.URL.RawQuery)
	check(err)

	code := params["code"][0]
	token := getAccessToken(clientID, clientSecret, code)

	io.WriteString(w, "Received authorization code. You can now close this browser window.")

	writeAccessToken(company, token)

	go os.Exit(0)
}

//
// Request an access token based on the client id, client secret and received authorization code.
//
func getAccessToken(clientID string, clientSecret string, code string) Token {
	address := fmt.Sprintf("https://login.windows.net/common/oauth2/token")
	client := &http.Client{}
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("resource", "https://graph.windows.net")
	form.Set("redirect_uri", "http://localhost:27015/auth")

	resp, err := client.PostForm(address, form)
	check(err)

	content, err := ioutil.ReadAll(resp.Body)
	check(err)

	var token Token
	err = json.Unmarshal(content, &token)
	check(err)

	return token
}

//
// Write the received access token to disk.
//
func writeAccessToken(company string, token Token) {
	usr, err := user.Current()
	check(err)

	var credentials Credentials
	credentials.Company = company
	credentials.Token = token

	content, err := json.Marshal(credentials)
	check(err)

	err = ioutil.WriteFile(path.Join(usr.HomeDir, ".azurectl"), content, 0644)
	check(err)
}

//
// Read the credentials from disk.
//
func readCredentials() Credentials {
	var credentials Credentials

	usr, err := user.Current()
	check(err)

	content, err := ioutil.ReadFile(path.Join(usr.HomeDir, ".azurectl"))
	check(err)

	err = json.Unmarshal(content, &credentials)
	check(err)

	return credentials
}

//
// List the groups in Active Directory.
//
func listGroups(c *cli.Context) {
	credentials := readCredentials()

	address := fmt.Sprintf("https://graph.windows.net/%s/groups?api-version=1.6", credentials.Company)
	client := &http.Client{}
	req, err := http.NewRequest("GET", address, nil)
	req.Header.Add("Host", "graph.windows.net")
	req.Header.Add("Authorization", credentials.Token.AccessToken)
	req.Header.Add("Content-Type", "application/json")
	req.Close = true

	resp, err := client.Do(req)
	check(err)

	content, err := ioutil.ReadAll(resp.Body)
	check(err)

	fmt.Println(string(content))
}

//
// Get details about a group in Active Directory.
//
func getGroup(c *cli.Context) {
	if len(c.Args()) < 1 {
		cli.ShowSubcommandHelp(c)
		os.Exit(1)
	}

	groupID := c.Args()[0]
	credentials := readCredentials()

	address := fmt.Sprintf("https://graph.windows.net/%s/groups/%s?api-version=1.6", credentials.Company, groupID)
	client := &http.Client{}
	req, err := http.NewRequest("GET", address, nil)
	req.Header.Add("Host", "graph.windows.net")
	req.Header.Add("Authorization", credentials.Token.AccessToken)
	req.Header.Add("Content-Type", "application/json")
	req.Close = true

	resp, err := client.Do(req)
	check(err)

	content, err := ioutil.ReadAll(resp.Body)
	check(err)

	fmt.Println(string(content))
}

//
// Create a group in Active Directory.
//
func createGroup(c *cli.Context) {
	if len(c.Args()) < 1 {
		cli.ShowSubcommandHelp(c)
		os.Exit(1)
	}

	displayName := c.Args()[0]
	mailNickname := strings.TrimPrefix(displayName, ".")
	credentials := readCredentials()
	description := c.String("description")

	var group Group
	group.DisplayName = displayName
	group.MailNickname = mailNickname
	group.MailEnabled = false
	group.SecurityEnabled = true
	group.Description = description
	groupJSON, err := json.Marshal(group)
	check(err)

	address := fmt.Sprintf("https://graph.windows.net/%s/groups?api-version=1.6", credentials.Company)
	client := &http.Client{}
	req, err := http.NewRequest("POST", address, bytes.NewBuffer(groupJSON))
	req.Header.Add("Host", "graph.windows.net")
	req.Header.Add("Authorization", credentials.Token.AccessToken)
	req.Header.Add("Content-Type", "application/json")
	req.Close = true

	resp, err := client.Do(req)
	check(err)

	content, err := ioutil.ReadAll(resp.Body)
	check(err)

	fmt.Println(string(content))
}

//
// Delete a group from Active Directory.
//
func deleteGroup(c *cli.Context) {
	if len(c.Args()) < 1 {
		cli.ShowSubcommandHelp(c)
		os.Exit(1)
	}

	groupID := c.Args()[0]
	credentials := readCredentials()

	address := fmt.Sprintf("https://graph.windows.net/%s/groups/%s?api-version=1.6", credentials.Company, groupID)
	client := &http.Client{}
	req, err := http.NewRequest("DELETE", address, nil)
	req.Header.Add("Host", "graph.windows.net")
	req.Header.Add("Authorization", credentials.Token.AccessToken)
	req.Header.Add("Content-Type", "application/json")
	req.Close = true

	resp, err := client.Do(req)
	check(err)

	content, err := ioutil.ReadAll(resp.Body)
	check(err)

	fmt.Println(string(content))
}

//
// Handle errors in a common way.
//
func check(err error) {
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err.Error())
		os.Exit(1)
	}
}
