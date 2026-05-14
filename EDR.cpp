#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <winevt.h>
#include <string>
#include <map>
#include <vector>

using namespace std;

#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "User32.lib")

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent);
DWORD PrintEvent(EVT_HANDLE);
wstring ExtractScriptBlock(wstring&);
wstring ExtractProcessIDBlock(wstring&);
float ShannonEntropy(wstring);
int PopDialogBox(wstring, wstring);
bool ProcessKiller(wstring);
void ProcessResumer(wstring);
void ProcessSuspender(wstring);

vector<int> arr;

float finalEntropy = 0.0;
HANDLE g_hStopEvent = NULL;

typedef NTSTATUS (NTAPI *NtSuspendProcessPtr)(IN HANDLE ProcessHandle);
typedef NTSTATUS (NTAPI *NtResumeProcessPtr)(IN HANDLE ProcessHandle);



void main (void)
{
    DWORD status = ERROR_SUCCESS ;
    EVT_HANDLE hSubscription = NULL;
    LPWSTR pwsPath = L"Microsoft-Windows-PowerShell/Operational";
    LPWSTR pwsQuery = L"*[System[(EventID=4104)]]";
    g_hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    hSubscription = EvtSubscribe(NULL, NULL, pwsPath, pwsQuery, NULL, NULL, (EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback, EvtSubscribeToFutureEvents);

    if(hSubscription == NULL){
        status = GetLastError();

        if(status == ERROR_EVT_CHANNEL_NOT_FOUND)
            wprintf(L"Channel %s was not found. \n", pwsPath);
        else if(status == ERROR_EVT_INVALID_QUERY)
            wprintf(L"The query /%s/ was not valid.\n", pwsQuery);
        else 
            wprintf(L"EvtSubscribe failed with %lu. \n", status);
        
        goto cleanup;
    }

    wprintf(L"Listening for Events... (Ctrl+C) to Stop \n");
    WaitForSingleObject(g_hStopEvent, INFINITE);

    cleanup:
        if(hSubscription)
            EvtClose(hSubscription);
        if(g_hStopEvent)
            EvtClose(g_hStopEvent);
}

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent){
    DWORD status = ERROR_SUCCESS;

    switch(action){
        case EvtSubscribeActionError:
            if((DWORD)hEvent == ERROR_EVT_QUERY_RESULT_STALE)
                wprintf(L"The scubscription callback was notified that event records are missing.");
            else 
                wprintf(L"The subscription callback was received with the following error: %lu \n", (DWORD)hEvent);
            break;
        
        case EvtSubscribeActionDeliver:
            if((status=PrintEvent(hEvent)) != ERROR_SUCCESS){
                goto cleanup;
            }
            break;
        
        default:
            wprintf(L"SubscriptionCallback: Unkown Action.\n");
    }

    cleanup:
        if(status != ERROR_SUCCESS){
            wprintf(L"Callback failed with error %d \n", status);
            SetEvent(g_hStopEvent);
        }
    return status;
}

DWORD PrintEvent(EVT_HANDLE hEvent){
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    LPWSTR pRenderedContent = NULL;
    wstring cleanCode;
    wstring processID;

    if(!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount)){
        if((status = GetLastError())==ERROR_INSUFFICIENT_BUFFER){
            dwBufferSize = dwBufferUsed;
            pRenderedContent = (LPWSTR)malloc(dwBufferSize);
            if(pRenderedContent){
                EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
                wstring xmlData((LPWSTR)pRenderedContent);
                cleanCode = ExtractScriptBlock(xmlData);
                processID = ExtractProcessIDBlock(xmlData);
            }
            else{
                wprintf(L"malloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if((status = GetLastError()) != ERROR_SUCCESS){
            wprintf(L"EvtRender failed with status: %d \n", status);
            goto cleanup;
        }
    }
    //actual printing HERE
   
    if(!cleanCode.empty())
        finalEntropy =  ShannonEntropy(cleanCode);
        //check entropy, add the pid to a list, ignore it if its already in list
        if(finalEntropy>4.5){
            auto i = find(arr.begin(), arr.end(), stoi(processID));
            if (i == arr.end()){
                PopDialogBox(cleanCode, processID);
                arr.push_back(stoi(processID));
            }
        }
        wprintf(L"Code: %s\nEntropy:  %f\nProcessID: %s\n", cleanCode.c_str(), finalEntropy, processID.c_str());
    cleanup:
        if(pRenderedContent)
            free(pRenderedContent);
        return status;
}

wstring ExtractScriptBlock(wstring& xmlData){

    wstring scriptStartTag = L"<Data Name='ScriptBlockText'>";
    wstring scriptEndTag = L"</Data>";
    
    size_t scriptStartPos =xmlData.find(scriptStartTag);
    if (scriptStartPos == wstring::npos) return L"";

    scriptStartPos += scriptStartTag.length();

    size_t scriptEndPos = xmlData.find(scriptEndTag, scriptStartPos);
    if (scriptEndPos == wstring::npos) return L"";

    return xmlData.substr(scriptStartPos, scriptEndPos-scriptStartPos);

}

wstring ExtractProcessIDBlock(wstring& xmlData){
    wstring pidStartTag = L"ProcessID='";
    wstring pidEndTag = L"' ThreadID";
    
    size_t pidStartPos =xmlData.find(pidStartTag);
    if (pidStartPos == wstring::npos) return L"";

    pidStartPos += pidStartTag.length();

    size_t pidEndPos = xmlData.find(pidEndTag, pidStartPos);
    if (pidEndPos == wstring::npos) return L"";

    return xmlData.substr(pidStartPos, pidEndPos-pidStartPos);
    
}


float ShannonEntropy(wstring cleanCode){

    map<wchar_t, int> frequency;

    for(wchar_t c : cleanCode){
        frequency[c]++;
    }

    float entropy = 0.0;
    double totalChar = (double)cleanCode.length();

    for(auto const& [key, value] : frequency)
    {
        double p = (double)value / (double)totalChar; 
        entropy -= p * log2(p);

    }

    return entropy;
}

int PopDialogBox(wstring cleanLog, wstring processID){

    wstring previewLog = cleanLog;
    if(previewLog.length()>150)
        previewLog = cleanLog.substr(0,150);

    
    wstring warning = L"Threat detected, Kill it with Fire?  : \n\n" + previewLog + L"...";
    wstring goofyEDR = L"GoofyEDR";
    bool error=0;
    wstring text = L"";

    int msgBoxID = MessageBoxW(NULL, warning.c_str(), goofyEDR.c_str(), MB_OKCANCEL | MB_ICONWARNING);

    ProcessSuspender(processID);

    switch(msgBoxID){
        case IDOK:
            error = ProcessKiller(processID);
            if(error!=0) text = L"KILLED SUCCESSFULLY!!!\n\n";
            else text = L"COULD NOT KILL PRCOCESS :(\n\n";

            MessageBoxW(NULL, text.c_str(), goofyEDR.c_str(), MB_ICONEXCLAMATION);
            break;

        case IDCANCEL:
            ProcessResumer(processID);
            break;
    }
    return msgBoxID;
}

bool ProcessKiller(wstring pid){

    int pidInt = stoi(pid);
    DWORD pidDword = (DWORD)pidInt;

    HANDLE hProcessID = OpenProcess(PROCESS_TERMINATE, true, pidDword); 
    return TerminateProcess(hProcessID, 1);

}

void ProcessSuspender(wstring pid){ 
    int pidInt = stoi(pid);
    DWORD pidDword = (DWORD)pidInt;
  
    NtSuspendProcessPtr NtSuspendProcess = (NtSuspendProcessPtr)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSuspendProcess");

    HANDLE hProcessID = OpenProcess(PROCESS_SUSPEND_RESUME, true, pidDword);
    NtSuspendProcess(hProcessID);
}

void ProcessResumer(wstring pid){ 
    int pidInt = stoi(pid);
    DWORD pidDword = (DWORD)pidInt;

    NtResumeProcessPtr NtResumeProcess = (NtResumeProcessPtr)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeProcess");

    HANDLE hProcessID = OpenProcess(PROCESS_SUSPEND_RESUME, true, pidDword);
    NtResumeProcess(hProcessID);
}
