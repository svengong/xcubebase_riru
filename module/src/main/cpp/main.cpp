#include <jni.h>
#include <sys/types.h>
#include <riru.h>
#include <malloc.h>
#include <cstring>

#include "frida-gumjs-example.h"


#include <unistd.h>
#include <pthread.h>
#include <android/log.h>
#include <sys/stat.h>
#include <sys/wait.h>
//#include <stdio.h>
#define LOGTAG "Xcube_gumjshook"
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOGTAG , __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG , LOGTAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO , LOGTAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN , LOGTAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR , LOGTAG, __VA_ARGS__)
#if defined(__arm__)
#include "includes/armeabi-v7a/frida-gumjs.h"
#elif defined(__aarch64__)

#include "includes/arm64-v8a/frida-gumjs.h"
#endif

int mysystem(char *cmdstring, char *buf, int len);

static int enable_hack;
static jstring *_appDataDir;

// 仅在测试app生效
int rirutest(JNIEnv *env, jstring appDataDir) {

    if (!appDataDir) {
        LOGD("forkAndSpecializePre appDataDir null");
        return 0;
    }
    const char *app_data_dir = env->GetStringUTFChars(appDataDir, NULL);
    int user = 0;
    static char package_name[256];
    if (sscanf(app_data_dir, "/data/%*[^/]/%d/%s", &user, package_name) != 2) {
        if (sscanf(app_data_dir, "/data/%*[^/]/%s", package_name) != 1) {
            package_name[0] = '\0';
            LOGW("can't parse %s", app_data_dir);
            return 0;
        }
    }
    env->ReleaseStringUTFChars(appDataDir, app_data_dir);
//    LOGD("package [ %s ] starting...", package_name);

    char cmd_string[1024];
    const char *filepath = "/data/local/tmp/pkg.conf";
    sprintf(cmd_string, "cat %s", filepath);
    int bufsize = 1024 * 10;
    char buf[bufsize];
    mysystem(cmd_string, buf, bufsize);

    int ret = 0;
    char *item = NULL;
    char *delims = "\r\n";
    item = strtok(buf, delims);

    while (item != NULL) {
//        LOGD("package item: %s", item);
        if (strcmp(item, package_name) == 0) {
            ret = 1;
            break;
        } else {
            ret = 0;
        }
        item = strtok(NULL, delims);
    }
    return ret;
}

// 用readjs方法中的方式比较简单，但是由于尝试在zygote进程中读取文件，才试到这里的方法
// 这个方法作为一个通用方法就不改回去了
int mysystem(char *cmdstring, char *buf, int len) {
    int fd[2];
    pid_t pid;
    int n, count;
    memset(buf, 0, len);
    if (pipe(fd) < 0)
        return -1;
    if ((pid = fork()) < 0){
        LOGE("fork faild");
        return -1;
    }
    else if (pid > 0) {
        close(fd[1]);
        count = 0;
        while ((n = read(fd[0], buf + count, len)) > 0 && count > len)
            count += n;
        close(fd[0]);
        if (waitpid(pid, NULL, 0) > 0)
            return -1;
    } else {
        close(fd[0]);
        if (fd[1] != STDOUT_FILENO) {
            if (dup2(fd[1], STDOUT_FILENO) != STDOUT_FILENO) {
                return -1;
            }
            close(fd[1]);
        }
        if (execl("/system/bin/sh", "sh", "-c", cmdstring, (char *) 0) == -1){
            LOGE("execl (%s) faild", cmdstring);
            return -1;
        }

    }
    return 0;
}

static void forkAndSpecializePre(
        JNIEnv *env, jclass clazz, jint *_uid, jint *gid, jintArray *gids, jint *runtimeFlags,
        jobjectArray *rlimits, jint *mountExternal, jstring *seInfo, jstring *niceName,
        jintArray *fdsToClose, jintArray *fdsToIgnore, jboolean *is_child_zygote,
        jstring *instructionSet, jstring *appDataDir, jboolean *isTopApp,
        jobjectArray *pkgDataInfoList,
        jobjectArray *whitelistedDataInfoList, jboolean *bindMountAppDataDirs,
        jboolean *bindMountAppStorageDirs) {

//    enable_hack = rirutest(env, *appDataDir);
    _appDataDir = appDataDir;
    // in zygote process,
}

static void forkAndSpecializePost(JNIEnv *env, jclass clazz, jint res) {
    if (res == 0) {
        // in app process
        enable_hack = rirutest(env, *_appDataDir);
        if (enable_hack) {
            gumjsHook();
        }

    } else {
        // in zygote process, res is child pid
        // don't print log here, see https://github.com/RikkaApps/Riru/blob/77adfd6a4a6a81bfd20569c910bc4854f2f84f5e/riru-core/jni/main/jni_native_method.cpp#L55-L66
    }
}

static void specializeAppProcessPre(
        JNIEnv *env, jclass clazz, jint *_uid, jint *gid, jintArray *gids, jint *runtimeFlags,
        jobjectArray *rlimits, jint *mountExternal, jstring *seInfo, jstring *niceName,
        jboolean *startChildZygote, jstring *instructionSet, jstring *appDataDir,
        jboolean *isTopApp, jobjectArray *pkgDataInfoList, jobjectArray *whitelistedDataInfoList,
        jboolean *bindMountAppDataDirs, jboolean *bindMountAppStorageDirs) {
    // added from Android 10, but disabled at least in Google Pixel devices
}

static void specializeAppProcessPost(
        JNIEnv *env, jclass clazz) {
    // added from Android 10, but disabled at least in Google Pixel devices
}

static void forkSystemServerPre(
        JNIEnv *env, jclass clazz, uid_t *uid, gid_t *gid, jintArray *gids, jint *runtimeFlags,
        jobjectArray *rlimits, jlong *permittedCapabilities, jlong *effectiveCapabilities) {

}

static void forkSystemServerPost(JNIEnv *env, jclass clazz, jint res) {
    if (res == 0) {
        // in system server process
    } else {
        // in zygote process, res is child pid
        // don't print log here, see https://github.com/RikkaApps/Riru/blob/77adfd6a4a6a81bfd20569c910bc4854f2f84f5e/riru-core/jni/main/jni_native_method.cpp#L55-L66
    }
}

static int shouldSkipUid(int uid) {
    // by default, Riru only call module functions in "normal app processes" (10000 <= uid % 100000 <= 19999)
    // false = don't skip
    return false;
}

static void onModuleLoaded() {
    // called when the shared library of Riru core is loaded
}

extern "C" {

int riru_api_version;
RiruApiV9 *riru_api_v9;

/*
 * Init will be called three times.
 *
 * The first time:
 *   Returns the highest version number supported by both Riru and the module.
 *
 *   arg: (int *) Riru's API version
 *   returns: (int *) the highest possible API version
 *
 * The second time:
 *   Returns the RiruModuleX struct created by the module.
 *   (X is the return of the first call)
 *
 *   arg: (RiruApiVX *) RiruApi strcut, this pointer can be saved for further use
 *   returns: (RiruModuleX *) RiruModule strcut
 *
 * The second time:
 *   Let the module to cleanup (such as RiruModuleX struct created before).
 *
 *   arg: null
 *   returns: (ignored)
 *
 */
void *init(void *arg) {
    static int step = 0;
    step += 1;

    static void *_module;

    switch (step) {
        case 1: {
            auto core_max_api_version = *(int *) arg;
            riru_api_version =
                    core_max_api_version <= RIRU_MODULE_API_VERSION ? core_max_api_version
                                                                    : RIRU_MODULE_API_VERSION;
            return &riru_api_version;
        }
        case 2: {
            switch (riru_api_version) {
                // RiruApiV10 and RiruModuleInfoV10 are equal to V9
                case 10:
                case 9: {
                    riru_api_v9 = (RiruApiV9 *) arg;

                    auto module = (RiruModuleInfoV9 *) malloc(sizeof(RiruModuleInfoV9));
                    memset(module, 0, sizeof(RiruModuleInfoV9));
                    _module = module;

                    module->supportHide = true;

                    module->version = RIRU_MODULE_VERSION;
                    module->versionName = RIRU_MODULE_VERSION_NAME;
                    module->onModuleLoaded = onModuleLoaded;
                    module->shouldSkipUid = shouldSkipUid;
                    module->forkAndSpecializePre = forkAndSpecializePre;
                    module->forkAndSpecializePost = forkAndSpecializePost;
                    module->specializeAppProcessPre = specializeAppProcessPre;
                    module->specializeAppProcessPost = specializeAppProcessPost;
                    module->forkSystemServerPre = forkSystemServerPre;
                    module->forkSystemServerPost = forkSystemServerPost;
                    return module;
                }
                default: {
                    return nullptr;
                }
            }
        }
        case 3: {
            free(_module);
            return nullptr;
        }
        default: {
            return nullptr;
        }
    }
}
}