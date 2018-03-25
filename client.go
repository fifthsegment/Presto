package main;
import (
	"github.com/valyala/fasthttp"
	"github.com/tidwall/buntdb"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
	"encoding/json"
	"strings"
	"strconv"
	"net/http"
	"net/url"
	"bytes"
	"io"
	"mime/multipart"
	"bufio"
	"io/ioutil"
	"crypto/sha256"
	"encoding/hex"

)

var AIClient *fasthttp.Client
var DefClient *http.Client
var JWToken string  = ""
var APIBase string  = "http://localhost:8080/api"
var UploadPath string
var DownloadPath string
var TempDownloadPath string
var ClientStorageDatabase *buntdb.DB 
var PathStorage map[int]string 
var ServerDownloadConfig ServerDownloadConfigStruct

type Asset struct {
	FilePath string    `json:"FilePath"`
	Name string    `json:"Name"`
	IsDir bool `json:"IsDir"`
	Size int64 `json:"Size"`
	ModTime string `json:"ModTime"`
	Modified bool `json:"Modified"` //modified since last upload
	RemoteID int64 `json:"RemoteID"`
	DirLevel int `json:"DirLevel"`
	ParentPath string `json:"ParentPath"`

}

type ServerResponse struct{
	T int64    `json:"T"`
	Token string `json:"token"`
	Error bool `json:"error"`
	Valid bool `json:"valid"`
	ErrorCode int  `json:"errorcode"`
}

type ServerResponseAsset struct {
    Name string    `json:"name"`
    TName string    `json:"tname"`
    Age int    `json:"age"`
    Ts int64    `json:"ts"`
    IsDir  bool `json:"isDir"`
    InFolder  int `json:"inFolder"`
    Extension  string `json:"extension"`
    // AbsPath  string `json:"abspath"`
    T string `json:t`
    Thumbnail string `json:thumbnail`
    Hash string `json:hash`
}

type ServerDownloadConfigStruct struct{
	DownloadBase string    `json:"downloadBase"`
}

func useResponseBody(body []byte) int64 {
    // (string(body));
    var r ServerResponse
    json.Unmarshal(body, &r)
    return r.T;
}

func useResponseBodyStruct(body []byte) ServerResponse {
    // (string(body));
    var r ServerResponse
    json.Unmarshal(body, &r)
    return r;
}

func PerformRequestJSONResp(method string, endpoint string, formData url.Values )[]byte{
    switch (method){
    	case "GET":
    		req, err := http.NewRequest(method, APIBase+endpoint, nil)
			req.Header.Set("Authorization", JWToken)
		    resp, err := DefClient.Do(req)
		    if err != nil{
		        log.Fatal(err)
		    }
		    bodyText, err := ioutil.ReadAll(resp.Body)
		    return bodyText
		case "POST":
			req, err := http.NewRequest("POST", APIBase+endpoint, strings.NewReader(formData.Encode()))	
			req.Header.Set("Authorization", JWToken)
		    req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		    resp, err := DefClient.Do(req)
		    if err != nil{
		        log.Fatal(err)
		    }
		    bodyText, err := ioutil.ReadAll(resp.Body)
		    return bodyText
    	break;
    }
    return nil;
    // s := string(bodyText)

    // fmt.Println(s)
}

func PerformGETRequest( endpoint string ) string {
	// Fetch google page via local proxy.
    statusCode, body, err := AIClient.Get(nil, APIBase+endpoint)
    if err != nil {
        log.Fatalf("Error when loading page through local proxy: %s", err)
    }
    if statusCode != fasthttp.StatusOK {
        log.Fatalf("Unexpected status code: %d. Expecting %d", statusCode, fasthttp.StatusOK)
    }
    return string(body)
}

func PerformPOSTRequest( endpoint string, args *fasthttp.Args )int64{
	// Fetch google page via local proxy.
    statusCode, body, err := AIClient.Post(nil, APIBase+endpoint, args)
    if err != nil {
        log.Fatalf("Error when loading ednpoint through local proxy: %s", err)
    }
    if statusCode != fasthttp.StatusOK {
        log.Fatalf("Unexpected status code: %d. Expecting %d", statusCode, fasthttp.StatusOK)
    }
    return useResponseBody(body)
}

func PerformPOSTRequestJSONResp( endpoint string, args *fasthttp.Args )ServerResponse{
	// Fetch google page via local proxy.
    statusCode, body, err := AIClient.Post(nil, APIBase+endpoint, args)
    if err != nil {
        log.Fatalf("Error when loading ednpoint through local proxy: %s", err)
    }
    if statusCode != fasthttp.StatusOK {
        log.Fatalf("Unexpected status code: %d. Expecting %d", statusCode, fasthttp.StatusOK)
    }
    return useResponseBodyStruct(body)
}

func PerformRequest( method string, endpoint string ){
	switch(method){
		case "GET":
			PerformGETRequest(endpoint)
			break;
	}
}

func AssetPreUploadCheck(name string, path string) bool {
	if (name == "AIClientDB.db"){
		return false;
	}
	return true;
}

func RemoteCreateDir(name string, parent string ) int64 {
	// log.Println("Uploading : "+name)
	// var args fasthttp.Args;
	// args.Add("name", name)
	// args.Add("parent",parent);
	form := url.Values{}
    form.Add("name", name)
    form.Add("parent", parent)
	// return PerformPOSTRequest("/folder/create", &args)
	resp:=PerformRequestJSONResp("POST", "/folder/create", form)
	var r ServerResponse
	json.Unmarshal(resp, &r)
	return r.T;
	// return 0;
}
func newfileUploadRequest(uri string, 
	params map[string]string, paramName, path string) (*http.Request, error) {
	file, err := os.Open(path)
	if err != nil {
	  return nil, err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(paramName, filepath.Base(path))
	if err != nil {
	  return nil, err
	}
	_, err = io.Copy(part, file)

	for key, val := range params {
	  _ = writer.WriteField(key, val)
	}
	err = writer.Close()
	if err != nil {
	  return nil, err
	}

	req, err := http.NewRequest("POST", uri, body)
	req.Header.Set("Authorization",JWToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req, err
}

func performFileUpload(endpoint string, path string, parent string )int64{
	log.Println("Performing File Upload on endpoint = " + endpoint)
	extraParams := map[string]string{
		// "parent":       parent,
		// "author":      "Matt Aimonetti",
		// "description": "A document with all the Go programming language secrets",
	}
	if (parent != ""){
		extraParams["parent"] = parent;
	}
	request, err := newfileUploadRequest(APIBase+ endpoint, extraParams, "file", path)
	if err != nil {
	  log.Fatal(err)
	}
	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
	  log.Fatal(err)
	} else {
	  	body := &bytes.Buffer{}
		  _, err := body.ReadFrom(resp.Body)
		if err != nil {
		      log.Fatal(err)
		  }
		resp.Body.Close()
		var r ServerResponse
	    json.Unmarshal(body.Bytes(), &r)
	    return r.T;
	}
	return 0;
}

func RemoteCreateAsset(name string, path string, parent string ) int64 {
	upload:=AssetPreUploadCheck(name, path)
	if (upload){
		log.Println("Uploading : "+name)
		return performFileUpload("/asset/create", path, parent)
		// return 0;
	}
	return -1;
}

func RemoteUpdateAsset(id string, name string, path string ) int64 {
	log.Println("Updating asset = " + name)

	upload:=AssetPreUploadCheck(name, path)
	if (upload){
		log.Println("Uploading : "+name)
		return performFileUpload("/assets/"+id, path, "")
		// return 0;
	}
	return -1;
}


func visit(path string, f os.FileInfo, err error) error {
  // fmt.Printf("Visited: %s\n", path)
  name:= f.Name();
  isDir := f.IsDir();
  if (isDir){
  	_=name
  	// RemoteCreateDir(name, "0")
  }else{
  	// RemoteCreateAsset(name, path, "0")
  }
  return nil
} 

func GetDirLevel(path string ) int{
	ns := strings.Replace( path, UploadPath, "", -1)
	return strings.Count(ns , "/");
}

func GetParentPath( path string ) string {
	index := strings.LastIndex(path, "/")
	newpath := path[0:index]
	// ns := strings.Replace( path, UploadPath, "", -1)
	// lastDir := path.substring(path.lastIndexOf('/') + 1);
	return newpath;
}

func UpdateInDb(path string, name string, isDir bool, size int64, modTime time.Time){
	var asset Asset;
	var found = false;
	// fmt.Println("-----Updating in db-----")
	// fmt.Println("Path " + path)
	ClientStorageDatabase.View(func(tx *buntdb.Tx) error {
		// query := "{\"FilePath\": "+path+"}"
		query := path;
		_ = query
		str, err := tx.Get(path)
		if (err==nil){
			err := json.Unmarshal([]byte(str), &asset)
			if (err!=nil){
				log.Fatalf(string(err.Error()) );
			}
			found = true;

		}else{
			// log.Fatalf(string(err.Error()) );
		}

		return nil
	})
	modified := false;
	if (found){
		xxs:=strconv.FormatInt(asset.RemoteID, 10)
		onRemote:=CheckIfAssetExistsOnRemote(xxs, asset)
		if !onRemote {
			asset.RemoteID = 0;
		}
		// fmt.Println(asset);
		asset.Name = name
		asset.Size = size;
		// asset.ModTime = modTime.Format(time.UnixDate)
		 // := asset.modTime
		curTime, _ := time.Parse(time.UnixDate, modTime.Format(time.UnixDate))
		// log.Println("Mod Time = " + curTime.String())
		prevTime, _ := time.Parse(time.UnixDate, asset.ModTime)
		// log.Println("Pre Time = " + prevTime.String())
		if (curTime.After(prevTime)){
			modified = true;
			asset.ModTime = modTime.Format(time.UnixDate)
		}
	}else{
		asset.Name = name
		asset.Size = size;
		asset.ModTime = modTime.Format(time.UnixDate)
	}
	// _=modified
	if (modified){
		log.Println("File was modified = " + name);
	}
	asset.Modified = modified;
	asset.IsDir = isDir
	asset.FilePath = path;
	if (asset.IsDir){
		asset.DirLevel = GetDirLevel(path);
		PathStorage[asset.DirLevel] = path;
		asset.ParentPath = GetParentPath(path)
		// fmt.Println("Parent = " +asset.ParentPath);
		// fmt.Println("FilePath = "+asset.FilePath);
		// if (asset.DirLevel == 0){
		// 	asset.ParentPath = path
		// }else{
		// 	PathStorage[asset.DirLevel] 
		// }
	}else{
		asset.DirLevel = -10;
		asset.ParentPath = GetParentPath(path)
	}
	
	ClientStorageDatabase.Update(func(tx *buntdb.Tx) error {
		json.Marshal(asset)
		b, err := json.Marshal(asset)
		if err != nil {
			log.Fatalf(string(err.Error()) );
		}else{
			tx.Set(path,string(b),nil);
			// fmt.Println("Updated in db")
		}
		
		return nil
	})

}

func GenerateMapVisit(path string, f os.FileInfo, err error) error {
	name:= f.Name();
  	isDir := f.IsDir();
	if (isDir){
  		UpdateInDb(path, name, true, 0, f.ModTime() )
  	}else{
  		UpdateInDb(path, name, false, f.Size(), f.ModTime()  )
  	}
  	return nil
}

func GenerateMap(){
	PathStorage = make(map[int]string)
	// for i := 0; i < 100; i++ {
	// 	PathStorage[i] = "s"
	// }
	
	err := filepath.Walk(UploadPath, GenerateMapVisit)
	if err!= nil{
		panic(err)
	}
	
}

func initApp(){
	datastore:="AIClientDB.db"
	// localdeleteFile(datastore)
	ClientStorageDatabase, _ = buntdb.Open(datastore)
	ClientStorageDatabase.Shrink()
	ClientStorageDatabase.CreateIndex("Base", "*", buntdb.IndexString)
	ClientStorageDatabase.CreateIndex("name", "*", buntdb.IndexJSON("Name"))
	ClientStorageDatabase.CreateIndex("dirlevel", "*", buntdb.IndexJSON("DirLevel"))
	// ClientStorageDatabase.Update(func(tx *buntdb.Tx) error {
	// 	// tx.Set("/home/abdullah/Desktop/ProjectSwitcher/Switcher-FileServer/SyncClient/client.go", `{"FilePath": "/home/abdullah/Desktop/ProjectSwitcher/Switcher-FileServer/SyncClient/client.go"}`, nil)
	// 	return nil
	// })
	GenerateMap()
}

func GetLevelRemoteID(assets []Asset, level int, parentPath string) int64 {
	if (level == 0){
		return 0;
	}
	count := len(assets);
	for i := 0; i < count; i++ {
		asset := assets[i];
		if (asset.FilePath == parentPath){
			return asset.RemoteID;
		}
	}
	return 0;
}

func GetLevelRemoteIDNew(assets []Asset, level int, parentPath string) int64 {
	if (level == 0){
		return 0;
	}
	count := len(assets);
	// fmt.Println("Checking in assets of size = " + strconv.Itoa(len(assets)))
	for i := 0; i < count; i++ {
		asset := assets[i];
		if (asset.FilePath == parentPath){
			// fmt.Println("Found a Parent for = " + asset.Name + " in Path = ")
			return asset.RemoteID;
		}
	}
	return 0;
}

func UploadFromDb( foldersOnly bool ){
	fmt.Println("Uploading from db");
	assetArray := []Asset{}
	ClientStorageDatabase.View( func(tx *buntdb.Tx) error {
		// query := "{\"inFolder\": "+id+"}"
		// fmt.Println("Running query")
		tx.Ascend("dirlevel",func(key, value string) bool {
			var asset Asset;
			
			err := json.Unmarshal([]byte(value), &asset)
			if (err!=nil){
				log.Fatalf(string(err.Error()) );
			}else{
				if (foldersOnly){
					/**
					* Create Directories
					*/
					if (asset.IsDir){
						if (asset.RemoteID == 0){
							// parentPath := ""
							// if (asset.DirLevel != 0){
							// 	parentPath = PathStorage[asset.DirLevel-1]
							// }
							// parentAssetValue, _ := tx.Get(parentPath)
							levelRemoteID := GetLevelRemoteIDNew(assetArray, asset.DirLevel, asset.ParentPath)
							fmt.Println("Name = " + asset.Name + " Level = "+ strconv.Itoa(asset.DirLevel) );
							remoteId := RemoteCreateDir(asset.Name, strconv.FormatInt(levelRemoteID, 10))
							asset.RemoteID = remoteId;
							assetArray = append(assetArray, asset);
							fmt.Println("Remote ID = " + strconv.FormatInt(remoteId, 10) )
						}else {
							if (asset.Modified){
								fmt.Println("Update Asset on server");
							}
						}						
					}else{
						//Create files
						if (asset.RemoteID == 0){

							// remoteId := RemoteCreateAsset(asset.Name, key, xxs)
							// _=remoteId
						}else{

						}
					}
				}

			}
			
			return true;
		})
		return nil;
	})
	fmt.Println("Updating in Database");
	ClientStorageDatabase.Update( func(tx *buntdb.Tx) error {
		count := len(assetArray)
		for i := 0; i < count; i++ {
			asset := assetArray[i];
			json.Marshal(asset)
			b, err := json.Marshal(asset)
			if err != nil {
				log.Fatalf(string(err.Error()) );
			}else{
				tx.Set(asset.FilePath,string(b),nil);
			}			
		}
		return nil;

	});
}

func CheckIfAssetExistsOnRemote(id string, asset Asset)bool{
	log.Println("Checking if asset exists on remote");

	resp:=PerformRequestJSONResp("GET", "/assets/"+id, nil)
	var r ServerResponse
	json.Unmarshal(resp, &r)
	fmt.Println(string(resp))
	if (r.ErrorCode == 2){
		/**
		* File doesn't exist
		*/
		log.Println("Doesnt exist on the remote")
		return false;
	}
	
	return true;
	// PerformRequestJSONResp()

}

func UploadFromDbFile( ){
	fmt.Println("Uploading from db");
	assetArrayDir := []Asset{}
	assetArray := []Asset{}
	ClientStorageDatabase.View( func(tx *buntdb.Tx) error {
		tx.Ascend("dirlevel",func(key, value string) bool {
			var asset Asset;
			err := json.Unmarshal([]byte(value), &asset)
			if (err!=nil){
				log.Fatalf(string(err.Error()) );
			}else{
				if (asset.IsDir){
					assetArrayDir = append(assetArrayDir, asset);
				}else{
					//Create files
				}
			}
			return true;
		})
		return nil;
	})
	ClientStorageDatabase.View( func(tx *buntdb.Tx) error {
		tx.Ascend("dirlevel",func(key, value string) bool {
			var asset Asset;
			err := json.Unmarshal([]byte(value), &asset)
			if (err!=nil){
				log.Fatalf(string(err.Error()) );
			}else{
				if (!asset.IsDir){
					if (asset.RemoteID == 0){
						levelRemoteID := GetLevelRemoteIDNew(assetArrayDir, asset.DirLevel, asset.ParentPath)
						xxs:=strconv.FormatInt(levelRemoteID, 10)
						// fmt.Println("Parent for = "+ asset.Name+" Parent = " + xxs);
						remoteAssetId := RemoteCreateAsset(asset.Name, key, xxs)
						// remoteAssetIdString:=strconv.FormatInt(remoteAssetId, 10)
						// fmt.Println("Remote Asset ID = " + remoteAssetIdString)
						asset.RemoteID = remoteAssetId
						assetArray = append(assetArray, asset)
					}else{
						xxs:=strconv.FormatInt(asset.RemoteID, 10)
						/**
						* This does not currently work
						*/
						RemoteUpdateAsset(xxs, asset.Name, key)
					}
				}
			}
			return true;
		})
		return nil;
	})
	ClientStorageDatabase.Update( func(tx *buntdb.Tx) error {
		count := len(assetArray)
		for i := 0; i < count; i++ {
			asset := assetArray[i];
			json.Marshal(asset)
			b, err := json.Marshal(asset)
			if err != nil {
				log.Fatalf(string(err.Error()) );
			}else{
				fmt.Println("Asset = " + asset.Name)
				fmt.Println(asset.RemoteID);
				tx.Set(asset.FilePath,string(b),nil);
			}			
		}
		return nil;
	});
}

func PushUpstream(){
	UploadFromDb( true )
    ClientStorageDatabase.Shrink()
    UploadFromDbFile()
    ClientStorageDatabase.Shrink()
}
func GetFileHash(filePath string) (result string, err error) {
    file, err := os.Open(filePath)
    if err != nil {
        return
    }
    defer file.Close()

    hash := sha256.New()
    _, err = io.Copy(hash, file)
    if err != nil {
        return
    }

    result = hex.EncodeToString(hash.Sum(nil))
    return
}
func DownloadDataFile(asset ServerResponseAsset, savePath string ){
	downloadLink := APIBase + ServerDownloadConfig.DownloadBase + asset.TName
	// log.Println(downloadLink)
	fileNameWithPath := savePath + string(os.PathSeparator) +asset.Name + "."+ asset.Extension
	// resp := PerformGETRequest(ServerDownloadConfig.DownloadBase + asset.TName)
	/**
	* Check if file exists
	* Take its hash if it does
	*/
	hash, _ :=GetFileHash(fileNameWithPath)
	if (hash == asset.Hash){
		log.Println("Hash is same, no need to download")
		return;
	}else{
	    fi, err := os.Stat(fileNameWithPath)
	    if err != nil {
	        /**
	        *
			* File prob doesn't exist
	        */
	        // return
	    }else{
	    	localFileModTime := fi.ModTime()
	    	remoteFileModTime :=  time.Unix(asset.Ts,0)
	    	if (remoteFileModTime.After(localFileModTime)){
	    		//continue
	    	}else{
	    		log.Println("File on remote is newer, downloading it.")
	    	}

	    }
	    	
	}
	out, err := os.Create(fileNameWithPath)
	defer out.Close()
	log.Println("Downloading File ->" + downloadLink)
	resp, err := http.Get(downloadLink)
	if err != nil{
		log.Println("Unable to download file : " + downloadLink)
		return
	}
	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	// ioutil.WriteFile(, []byte(resp), os.ModePerm)
}

func DataPuller(startFolderId int, newFolder string ){
	changePath := DownloadPath
	if (startFolderId > 0){
		newPath := TempDownloadPath+string(os.PathSeparator)+newFolder
		TempDownloadPath = newPath
		changePath = newPath;
	}
	log.Println("Changing to " + changePath )
	err := os.Chdir(changePath)
	if err != nil {
		e:=os.MkdirAll(changePath, os.ModePerm)
		if e!=nil{
			fmt.Println(string(e.Error()) )
		}else{
			// fmt.Println(string(e.Error()) )
		}
	    
	}
	var assets []ServerResponseAsset
	resp := PerformRequestJSONResp("GET", "/folders/"+strconv.Itoa(startFolderId),nil)
	json.Unmarshal([]byte(resp), &assets)
	count := len(assets)
	for i := 0; i < count; i++ {
		asset := assets[i]
		if (asset.IsDir){
			// e:=os.Mkdir(asset.Name, os.ModePerm)
			// if (e!=nil){
			// 	panic(e);
			// }
			b, _:=strconv.Atoi(asset.T)
			DataPuller(b, asset.Name)
		}else{
			DownloadDataFile(asset, TempDownloadPath)
		}
	}
	index := strings.LastIndex(TempDownloadPath, "/")
	TempDownloadPath = TempDownloadPath[0:index]
	// TempDownloadPath = strings.Replace(TempDownloadPath, string(os.PathSeparator)+newFolder, "", -1)
	os.Chdir(TempDownloadPath)
}

func PullDownStreamPre(){
	log.Println("Downloading Config...");
	// PerformRequestJSONResp
	resp := PerformRequestJSONResp("GET", "/config/", nil)
	json.Unmarshal([]byte(resp), &ServerDownloadConfig)
	fmt.Println(ServerDownloadConfig)
}


func PullDownStream(){
	PullDownStreamPre()
	fmt.Println("Will Pull to : " + DownloadPath);
	startFolderId := 0;
	DataPuller(startFolderId, "")
}

func localdeleteFile(path string) {
	// delete file
	var err = os.Remove(path)
	if isError(err) { return }

	fmt.Println("==> removing old db")
}

func isError(err error) bool {
	if err != nil {
		fmt.Println(err.Error())
	}

	return (err != nil)
}


func CheckIfLoginRequired() bool {
	data, err := ioutil.ReadFile("token.json")
	if (err!=nil){
		log.Println("ERROR: Token File Not found")
		return true;
	}else{
		var r ServerResponse
		json.Unmarshal(data, &r)
		if (len(r.Token) > 10 ){
			log.Println("Token found! Verifying token...")
			JWToken = r.Token
			resp:=PerformRequestJSONResp("GET", "/web/token/verify", nil)
			var s ServerResponse
			json.Unmarshal(resp, &s)
			if (s.Valid){
				log.Println("SUCCESS! Token is valid")
				return false;
			}else{
				log.Println("ERROR: Token is invalid")
				return true;
			}
		}
	}
	return true;
}

func LoginToServer(){
	keepRunning := true;
	for {
		fmt.Println("Username: ")
		reader := bufio.NewReader(os.Stdin)
	    username, _ := reader.ReadString('\n')

	    fmt.Println("Password: ")
		reader = bufio.NewReader(os.Stdin)
	    password, _ := reader.ReadString('\n')

	    username = strings.Replace(username, "\n", "", -1)
	    password = strings.Replace(password, "\n", "", -1)
	    fmt.Println("Server : " + APIBase)
	    fmt.Println("Attempting to login with "+ username + ":" + password)

	    log.Println("Contacting : "+ APIBase)
		var args fasthttp.Args;
		args.Add("username", username)
		args.Add("password",password);
		resp := PerformPOSTRequestJSONResp("/app/token", &args)
		if resp.Error{
			fmt.Println("Unable to validate your username and password")
		}else{
			keepRunning = false;
			fmt.Println("Login Succesful")
			bb, _:=json.Marshal(resp)
			ioutil.WriteFile("token.json", bb, 0666);
		}
		if (!keepRunning){
			break
		}
	}

}

func main(){
	APIBase = "http://localhost:8080/api"
	// fmt.Println("Running client...");
	c := &fasthttp.Client{	}
	DefClient = &http.Client{
		Timeout: time.Second * 10,
	}
	AIClient = c;

	ex, err := os.Executable()
    if err != nil {
        panic(err)
    }
    exPath := filepath.Dir(ex)

    UploadPath = exPath+ string(os.PathSeparator) + "UploadFromHere2"
    DownloadPath = exPath + string(os.PathSeparator) + "DownloadHere2"
    TempDownloadPath = exPath + string(os.PathSeparator) + "DownloadHere2"
    fmt.Println("Starting in :")
    fmt.Println(exPath)


    

    loginRequired:=CheckIfLoginRequired()
    if loginRequired {
    	LoginToServer()
    }
    fmt.Println("What would you like to do ?")
    fmt.Println("1- Push up stream")
    fmt.Println("2- Pull down stream")
    reader := bufio.NewReader(os.Stdin)
    text, _ := reader.ReadString('\n')
    if (text == "1\n"){
    	fmt.Println("Pushing Upstream");
    	initApp()
    	PushUpstream();
    }else{
    	fmt.Println("Pulling Downstream");
    	PullDownStream();
    }

    // PullDownStream();

}
