package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"io"
	"strings"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"path/filepath"
	"encoding/base64"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

var _rootDir = ""
func rootDir() string {
	if _rootDir == "" {
		log.Fatal("root dir not initialized")
	}
	return _rootDir
}

var _installDir = ""
func installDir() string {
	if _installDir == "" {
		log.Fatal("install dir not initialized")
	}
	return _installDir
}

var _fileServeRequestPath = "/fs/"

func fileServeRequestPath() string {
	return _fileServeRequestPath
}

var _password = ""

func Password() string {
	if _password == "" {
		log.Fatal("password not initialized")
	}
	return _password
}

func GenerateRandomBytes(n int) ([]byte, error) {
    b := make([]byte, n)
    _, err := rand.Read(b)
    // Note that err == nil only if we read len(b) bytes.
    if err != nil {
        return nil, err
    }
    return b, nil
}

func GenerateRandomString(s int) (string, error) {
    b, err := GenerateRandomBytes(s)
    return base64.URLEncoding.EncodeToString(b), err
}

func ToSha1(s string) [20]byte {
	data := []byte(s)
	return sha1.Sum(data)
}

func ToSha256(s string) [32]byte {
	data := []byte(s)
	return sha256.Sum256(data)
}

func ToHexString(bs [32]byte) string {
	s := ""
	for _, b := range bs {
		ds := fmt.Sprintf("%x", b)
		if len(ds) == 1 {
			ds = "0" + ds
		}
		s += ds
		//fmt.Println("ds len" + fmt.Sprint(len(ds)))
	}
	return s
}

func base64Encode(str string) string {
    return base64.StdEncoding.EncodeToString([]byte(str))
}

func base64Decode(str string) (string, bool) {
    data, err := base64.StdEncoding.DecodeString(str)
    if err != nil {
        return "", true
    }
    return string(data), false
}

func ReadFile(file string) string {
	dat, err := ioutil.ReadFile(file)
	check(err)
	return string(dat)
}

func WriteFile(contents string, file string) {
	bcontents := []byte(contents)
	err := ioutil.WriteFile(file, bcontents, 0644)
	check(err)
}

func WriteBinaryFile(contents []byte, file string){
	f, err := os.Create(file)
	f.Write(contents)
	check(err)
}

func main() {
	// parse command line flags
	rootPtr := flag.String("root", "", "The root file dir to serve files from")
	installPtr := flag.String("install", "", "The installation dir of mini-honey-server")
	pswdPtr := flag.String("pswd", "", "The password to use")
	httpsPtr := flag.String("protocol","https","The protocol to use. Either HTTP or HTTPS[default]")

	flag.Parse()
	if *installPtr == "" {
		dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			log.Fatal(err)
		}
		_installDir = dir
		fmt.Println("installation dir used:" + _installDir)
	} else {
		_installDir = *installPtr
	}

	if *httpsPtr == "" {
		*httpsPtr = "https"
	}

	if *rootPtr == "" {
		_rootDir = _installDir + string(os.PathSeparator) + "files"
		fmt.Println("root dir (files are served from here):" + _rootDir)
	} else {
		_rootDir = *rootPtr
	}

	if *pswdPtr == "" {
		log.Fatal("need to supply password")
	}
	_password = *pswdPtr

	http.HandleFunc(fileServeRequestPath(), serveFile)
	http.HandleFunc("/", serveTemplate)
	http.HandleFunc("/login", serveLogin)
	http.HandleFunc("/upload", handleUpload)
	http.HandleFunc("/move", handleMove)
	log.Println("Listening...")

	if *httpsPtr == "http" {
		http.ListenAndServe(":5000", nil)
	} else {
		if *httpsPtr == "https" {
			http.ListenAndServeTLS(":5000", "cert.pem", "key.pem", nil)
		} else {
			log.Fatal("protocol flag must be one of \"http\" | \"https\"")
		}
	}

	log.Println("Shutting down.")
}

func authorized(w http.ResponseWriter, r *http.Request) bool {
	sessCookie, err := r.Cookie("sessionid")
	if err != nil || sessCookie == nil {
		return false
	}
	attemptedpassword := fmt.Sprint(sessCookie.Value)
	// Use salt to add variation to password hashing
	saltCookie, err := r.Cookie("salt")
	if err != nil || saltCookie == nil {
		return false
	}
	salt := fmt.Sprint(saltCookie.Value)
	if len(salt) < saltLength() {
		return false
	}

	//fmt.Println("password attempt:" + attemptedpassword)

	correctpassword := ToHexString(ToSha256(Password()+salt))

	//fmt.Println("correct password:" + correctpassword)
	passwordsequal := stringCompare(attemptedpassword, correctpassword) //attemptedpassword == correctpassword
	//fmt.Println("bool:" + fmt.Sprint(passwordsequal))
	return passwordsequal
}

func stringCompare(s1, s2 string) bool {
	for idx1, c1 := range s1 {
		for idx2, c2 := range s2 {
			if idx1 == idx2 {
				if c1 != c2 {
					//fmt.Println(":::: index " + fmt.Sprint(idx1))
					//fmt.Println(":::: character " + fmt.Sprint(c1) + " isnt the same as " + fmt.Sprint(c2))
					return false
				}
			}
		}
	}
	return true
}

// -- Handling requests
func redirect(w http.ResponseWriter, r *http.Request, to string) {
    http.Redirect(w, r, to, 301)
}

func handleMove(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handleMove")
	movingFile := r.FormValue("moving-file")
	movingTo := r.FormValue("moving-to")
	fmt.Println("moving file "+movingFile+" to "+movingTo)
	movingFileArr := strings.Split(movingFile,"/")[4:]
	movingToArr := strings.Split(movingTo,"/")[3:]
	movingToArr = append(movingToArr,movingFileArr[len(movingFileArr)-1])
	fmt.Println(rootDir()+strings.Join(movingFileArr,"/")+","+
					rootDir()+strings.Join(movingToArr,"/"))
	fromString := rootDir()+strings.Join(movingFileArr,"/")
	toString := rootDir()+strings.Join(movingToArr,"/")
	err := os.Rename(fromString,toString)
  if err != nil {
		// try interpreting html escaped spaces,
		// as they are quite common.
		if strings.Contains(fromString,"%20") || strings.Contains(toString,"%20"){
			err = os.Rename(strings.Replace(fromString,"%20"," ",-1),
											strings.Replace(toString,"%20"," ",-1))
			if err != nil {
				log.Fatal(err)
			}
		} else {
  		log.Fatal(err)
		}
	}
}

// a great discussion of this topic can be found here:
// https://astaxie.gitbooks.io/build-web-application-with-golang/en/04.5.html
func handleUpload(w http.ResponseWriter, r *http.Request) {
           r.ParseMultipartForm(32 << 30)// TODO optimize this value?
					 fmt.Println("handleUpload")
           file, handler, err := r.FormFile("uploadfile")
           if err != nil {
               fmt.Println(err)
               return
           }
					 // first we convert the url passed in as url-Param
					 // to a valid dictionary path
					 //TODO: make this independent of base url (on the client)!!
					 theDir := strings.Replace(r.FormValue("thedir"),"~","/",-1)

					 fmt.Println("=> "+theDir)

					 defer file.Close()
           f, err := os.OpenFile(rootDir()+"/"+theDir+handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
           if err != nil {
               fmt.Println(err)
               return
           }
           defer f.Close()
           io.Copy(f, file)

					 // inform the user that the file upload was successful
					 s := ReadFile("site.html")
					 s = strings.Replace(s, "{{MainContent}}", "upload successful (use backspace to get back to parent directory!)", -1)
					 s = strings.Replace(s, "{{CSS}}", ReadFile("site.css"), -1)
					 fmt.Fprint(w, s)
}

func serveFile(w http.ResponseWriter, r *http.Request) {
	fmt.Print("running servefile ...")
	if authorized(w, r) {
		fmt.Print("authentication successful.")
		// -2 keeps the "/"
		flePath := string(r.URL.Path[1:])[len(fileServeRequestPath())-2:]
		http.ServeFile(w, r, rootDir()+flePath)
	} else {
		http.Error(w, "Unauthenticated access. Please login and try again!", 401)
	}
}


func saltLength() int {
	return 8
}

func serveLogin(w http.ResponseWriter, r *http.Request) {
	s := strings.Replace(ReadFile("site.html"), "{{MainContent}}", ReadFile("login.html"), -1)
	s = strings.Replace(s, "{{CSS}}", ReadFile("site.css"), -1)

	salt,err := GenerateRandomString(saltLength())
	check(err)
	saltCookie := http.Cookie{Name: "salt", Value: salt}
	http.SetCookie(w, &saltCookie)
	fmt.Fprint(w, s)
}

func serveTemplate(w http.ResponseWriter, r *http.Request) {
	requestedPath := r.URL.Path[0:]
	if authorized(w, r){
		s := ReadFile("site.html")
		s = strings.Replace(s, "{{MainContent}}", mainContentString(requestedPath), -1)
	  s = strings.Replace(s, "{{CSS}}", ReadFile("site.css"), -1)

		fmt.Fprint(w, s)
	} else {
		http.Error(w, "Unauthenticated access. Please login and try again!", 401)
	}
	//fmt.Fprintf(w, s)
}

func htmlRepresentFile(f os.FileInfo, dir string) string {
	nme := f.Name()
	html := ""
	switch mode := f.Mode(); {
	case mode.IsDir():
		// do directory stuff
		displaynme := nme
		if displaynme == ".." || len(displaynme) < 12 {
			displaynme = displaynme+"<p class=\"invisible-text\">#####</p>"
		}
		html = fmt.Sprintf("<div class=\"style-directory\"><a class=\"draggable\" href=\"%s\"/>%s</a></div>",
			strings.Replace(dir+"/"+nme, "//", "/", -1), displaynme)
	case mode.IsRegular():
		// do file stuff
		html = fmt.Sprintf("<div class=\"style-file\"><a class=\"draggable\" href=\"/fs/%s\">%s</a></div>", strings.Replace(dir+"/"+nme, "//", "/", -1), nme)
	}
	return html
}

func mainContentString(reqPathArg string) string {
	reqPath := reqPathArg
	log.Print("requesting path " + reqPath)
	s := ""
	files, err := ioutil.ReadDir(rootDir() + reqPath)
	parStat, err2 := os.Stat(rootDir() + reqPath + "/..")
	if err2 == nil {
		files = append(files, parStat)
		files = append([]os.FileInfo{parStat}, files...)
	}
	//files = append(files,"..")
	if err != nil {
		if reqPathArg == "" {
			log.Fatal(err)
		} else {
			return mainContentString("")
		}
	}
	for _, f := range files {
		s += htmlRepresentFile(f, reqPath)
	}
	return s
}
