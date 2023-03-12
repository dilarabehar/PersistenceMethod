#define SECURITY_WIN32
#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <comdef.h>       //com (component object model ) cesitli programlama dillerinde inter-process objesi olusturmak amacli kullanilir
                          //inter-process communication iki process arasindaki veri paylasimi. 
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma warning(disable : 4996)  //_wgetenv not safe

using namespace std;

#define TASKNAME L"Logon Trigger Test Task"

int __cdecl wmain()
{
    //  Get the windows directory and set the path to notepad.exe.
    wstring wstrExecutablePath = _wgetenv(L"WINDIR"); //windows installation directory 
    wstrExecutablePath += L"\\SYSTEM32\\NOTEPAD.EXE";

    //  Initialize COM  
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);  //com islevini baslatir ve es zamanlilik modelini (COINIT_MULTITHREADED) ayarlar.
    if (FAILED(hr)) return 1;

    //  Set general COM security levels. //process icin gerekli olan guvenlik degeri ayalar
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
    if (FAILED(hr))

    {
        CoUninitialize();
        return 1;
    }
    //ITASKSERVICE provide access to the task scheduler service for managing registered task.
    // cocreateinstance clsid ile iliskili classin objesini olusturur
    // IID_TaskService obje ile iletisim kurmak icin kullanilan interface(ITaskService) referans
    //interface pointer
    //  Create an instance of the Task Service.     
    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr))

    {
        CoUninitialize();
        return 1;
    }

    //  Connect to the task service.  ITaskService inerface methodu  connect local
    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr))
    {
        pService->Release();
        CoUninitialize();
        return 1;
    }

    //  Get the pointer to the root task folder.  This folder will hold the new task that is registered.
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr))
    {
        pService->Release();
        CoUninitialize();
        return 1;
    }

    //  If the same task exists, remove it. 
    pRootFolder->DeleteTask(_bstr_t(TASKNAME), 0);

    //  Create the task builder object to create the task.  taskin tum bilesenlerini icerir ITaskDefinition
    ITaskDefinition* pTask = NULL;
    hr = pService->NewTask(0, &pTask); // 

    // COM clean up.  Pointer is no longer used.    
    pService->Release();
    if (FAILED(hr)) { pRootFolder->Release(); CoUninitialize(); return 1; }

    //  Get the registration info for setting the identification.   
    IRegistrationInfo* pRegInfo = NULL;
    hr = pTask->get_RegistrationInfo(&pRegInfo);
    if (FAILED(hr))
    {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    BSTR MyBstr = SysAllocString(L"AUTHOR_NAME"); //supported string format in com library

    hr = pRegInfo->put_Author(MyBstr);  //Gets or sets the author of the task.
    pRegInfo->Release();
    if (FAILED(hr))
    {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    //  Create the settings for the task
    ITaskSettings* pSettings = NULL;     
    hr = pTask->get_Settings(&pSettings);
    if (FAILED(hr))
    {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    //  Set setting values for the task. 
    pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
    pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
    pSettings->put_ExecutionTimeLimit(_bstr_t(L"PT0S"));
    pSettings->Release();
    if (FAILED(hr))
    {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    //  Get the trigger collection to insert the logon trigger.
    //Gets or sets a collection of triggers used to start a task.
    ITriggerCollection* pTriggerCollection = NULL;
    hr = pTask->get_Triggers(&pTriggerCollection);
    if (FAILED(hr))
    {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    //  Add the logon trigger to the task.
    //creates a new trigger for the task
    ITrigger* pTrigger = NULL;
    hr = pTriggerCollection->Create(TASK_TRIGGER_LOGON, &pTrigger); //task trigger type enum TASK_TRIGGER_LOGON
    pTriggerCollection->Release();
    if (FAILED(hr))
    {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    ILogonTrigger* pLogonTrigger = NULL;   
    hr = pTrigger->QueryInterface(IID_ILogonTrigger, (void**)&pLogonTrigger);
    pTrigger->Release();
    if (FAILED(hr))
    {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    hr = pLogonTrigger->put_Id(_bstr_t(L"Trigger1"));  
    if (FAILED(hr)) {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    //  Define the user.  The task will execute when the user logs on. The specified user must be a user on this computer.  
    //hr = pLogonTrigger->put_UserId(_bstr_t(L"DOMAIN\\UserName"));

    pLogonTrigger->Release();
    if (FAILED(hr)) {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    IPrincipal* pPrincipal; //provide the security credentials 
    hr = pTask->get_Principal(&pPrincipal);
    if (FAILED(hr)) {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    hr = pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST); 
    if (FAILED(hr)) {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }


    //  Add an Action to the task. This task will execute .exe
    IActionCollection* pActionCollection = NULL;

    //  Get the task action collection pointer.
    hr = pTask->get_Actions(&pActionCollection);
    if (FAILED(hr)) {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    //  Create the action, specifying that it is an executable action.
    IAction* pAction = NULL;
    hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);  //task action type enum provides performs a command line operations
    pActionCollection->Release();
    if (FAILED(hr)) {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    //  QI for the executable task pointer.
    IExecAction* pExecAction = NULL;      //represents the action that execute the command line operations
    hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
    pAction->Release();
    if (FAILED(hr)) {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    //  Set the path of the executable.
    hr = pExecAction->put_Path(_bstr_t(wstrExecutablePath.c_str()));
    pExecAction->Release();
    if (FAILED(hr)) {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    //  Save the task in the root folder.
    IRegisteredTask* pRegisteredTask = NULL;   //provides the methods that are used to run the task immediately
    hr = pRootFolder->RegisterTaskDefinition(_bstr_t(TASKNAME), pTask, TASK_CREATE_OR_UPDATE, _variant_t(L"S-1-5-32-544"), _variant_t(), TASK_LOGON_GROUP, _variant_t(L""), &pRegisteredTask);      //_variant_t(L"Builtin\\Administrators"),
    if (FAILED(hr)) {
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return 1;
    }

    printf("Success! Task successfully registered.");
    getchar();

    pRootFolder->Release();
    pTask->Release();
    pRegisteredTask->Release();
    CoUninitialize();
    return 0;


}