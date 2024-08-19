#include "bindings.h"
#include <sys/inotify.h>

enum class InotifyEvents : uint32_t {
    _IN_ACCESS = 0x00000001,
    _IN_MODIFY = 0x00000002,
    _IN_ATTRIB = 0x00000004,
    _IN_CLOSE_WRITE = 0x00000008,
    _IN_CLOSE_NOWRITE = 0x00000010,
    _IN_OPEN = 0x00000020,
    _IN_MOVED_FROM = 0x00000040,
    _IN_MOVED_TO = 0x00000080,
    _IN_CREATE = 0x00000100,
    _IN_DELETE = 0x00000200,
    _IN_DELETE_SELF = 0x00000400,
    _IN_MOVE_SELF = 0x00000800,
    _IN_UNMOUNT = 0x00002000,
    _IN_Q_OVERFLOW = 0x00004000,
    _IN_IGNORED = 0x00008000,
    _IN_CLOSE = _IN_CLOSE_WRITE | _IN_CLOSE_NOWRITE,
    _IN_MOVE = _IN_MOVED_FROM | _IN_MOVED_TO,
    _IN_ONLYDIR = 0x01000000,
    _IN_DONT_FOLLOW = 0x02000000,
    _IN_EXCL_UNLINK = 0x04000000,
    _IN_MASK_CREATE = 0x10000000,
    _IN_MASK_ADD = 0x20000000,
    _IN_ISDIR = 0x40000000,
    _IN_ONESHOT = 0x80000000
};

std::mutex mod_vec_mutex;

void *thread_watch_intify_dump(void *arg) {
    char dirName[NAME_MAX] = {0};
    snprintf(dirName, NAME_MAX, "/proc/%d/%s", getpid(), (const char *)arg);
    int fd = inotify_init();
    if (fd < 0) {
        console->info("inotify_init err");
        return nullptr;
    }
    int wd = inotify_add_watch(fd, dirName, IN_ALL_EVENTS);
    if (wd < 0) {
        console->info("inotify_add_watch error | {} | {} | errno: {}", fd, dirName, errno);
        close(fd);
        return nullptr;
    }
    const int buflen = sizeof(struct inotify_event) * 0x100;
    char buf[buflen] = {0};
    fd_set readfds;
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        int iRet = select(fd + 1, &readfds, 0, 0, 0);
        if (-1 == iRet) {
            break;
        }
        if (iRet) {
            memset(buf, 0, buflen);
            int len = read(fd, buf, buflen);
            int i = 0;
            while (i < len) {
                struct inotify_event *event = (struct inotify_event *)&buf[i];
                console->info("event->mask: {}", magic_enum::enum_name(static_cast<InotifyEvents>(event->mask)));
                if ((event->mask == IN_OPEN)) {
                    bool open = false;
                    console->info("thread_watch_intify_dump {} -> _IN_OPEN  wd={:p}  len={}  name={}", dirName, event->wd, event->len, event->name);
                    if (std::strcmp(static_cast<char *>(arg), "maps") == 0) {
                        console->info("thread_watch_intify_dump < open maps >");
                    } else if (std::strcmp(static_cast<char *>(arg), "mem") == 0) {
                        console->info("thread_watch_intify_dump < open mem >");
                    } else if (std::strcmp(static_cast<char *>(arg), "pagemap") == 0) {
                        console->info("thread_watch_intify_dump < open pagemap >");
                    }
                }
                i += sizeof(struct inotify_event) + event->len;
            }
        }
    }
    inotify_rm_watch(fd, wd);
    close(fd);
    return nullptr;
}

void watch_MEM() {
    pthread_t tid;
    int ret = pthread_create(&tid, nullptr, thread_watch_intify_dump, (void *)"mem");
    if (ret != 0) {
        console->error("watchMEM pthread_create error");
    }
}

void watch_PAGEMAP() {
    pthread_t tid;
    int ret = pthread_create(&tid, nullptr, thread_watch_intify_dump, (void *)"pagemap");
    if (ret != 0) {
        console->error("watchPAGEMAP pthread_create error");
    }
}

void watch_MAPS() {
    pthread_t tid;
    int ret = pthread_create(&tid, nullptr, thread_watch_intify_dump, (void *)"maps");
    if (ret != 0) {
        console->error("watchMAPS pthread_create error");
    }
}

BINDFUNC(proc) {

    luabridge::getGlobalNamespace(L)
        .beginNamespace("proc")
        .addFunction("watch_MEM", watch_MEM)
        .addFunction("watch_PAGEMAP", watch_PAGEMAP)
        .addFunction("watch_MAPS", watch_MAPS)
        .endNamespace();
}