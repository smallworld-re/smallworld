#include <errno.h>
#include <string.h>
#include <stdlib.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    char *expected = NULL;
    char *actual = NULL; 
#ifdef EPERM
    expected = "Operation not permitted";
    actual = strerror(EPERM);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EPERM
#ifdef ENOENT
    expected = "No such file or directory";
    actual = strerror(ENOENT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOENT
#ifdef ESRCH
    expected = "No such process";
    actual = strerror(ESRCH);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ESRCH
#ifdef EINTR
    expected = "Interrupted system call";
    actual = strerror(EINTR);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EINTR
#ifdef EIO
    expected = "Input/output error";
    actual = strerror(EIO);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EIO
#ifdef ENXIO
    expected = "No such device or address";
    actual = strerror(ENXIO);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENXIO
#ifdef E2BIG
    expected = "Argument list too long";
    actual = strerror(E2BIG);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //E2BIG
#ifdef ENOEXEC
    expected = "Exec format error";
    actual = strerror(ENOEXEC);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOEXEC
#ifdef EBADF
    expected = "Bad file descriptor";
    actual = strerror(EBADF);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EBADF
#ifdef ECHILD
    expected = "No child processes";
    actual = strerror(ECHILD);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ECHILD
#ifdef EAGAIN
    expected = "Resource temporarily unavailable";
    actual = strerror(EAGAIN);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EAGAIN
#ifdef ENOMEM
    expected = "Cannot allocate memory";
    actual = strerror(ENOMEM);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOMEM
#ifdef EACCES
    expected = "Permission denied";
    actual = strerror(EACCES);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EACCES
#ifdef EFAULT
    expected = "Bad address";
    actual = strerror(EFAULT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EFAULT
#ifdef ENOTBLK
    expected = "Block device required";
    actual = strerror(ENOTBLK);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOTBLK
#ifdef EBUSY
    expected = "Device or resource busy";
    actual = strerror(EBUSY);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EBUSY
#ifdef EEXIST
    expected = "File exists";
    actual = strerror(EEXIST);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EEXIST
#ifdef EXDEV
    expected = "Invalid cross-device link";
    actual = strerror(EXDEV);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EXDEV
#ifdef ENODEV
    expected = "No such device";
    actual = strerror(ENODEV);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENODEV
#ifdef ENOTDIR
    expected = "Not a directory";
    actual = strerror(ENOTDIR);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOTDIR
#ifdef EISDIR
    expected = "Is a directory";
    actual = strerror(EISDIR);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EISDIR
#ifdef EINVAL
    expected = "Invalid argument";
    actual = strerror(EINVAL);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EINVAL
#ifdef ENFILE
    expected = "Too many open files in system";
    actual = strerror(ENFILE);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENFILE
#ifdef EMFILE
    expected = "Too many open files";
    actual = strerror(EMFILE);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EMFILE
#ifdef ENOTTY
    expected = "Inappropriate ioctl for device";
    actual = strerror(ENOTTY);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOTTY
#ifdef ETXTBSY
    expected = "Text file busy";
    actual = strerror(ETXTBSY);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ETXTBSY
#ifdef EFBIG
    expected = "File too large";
    actual = strerror(EFBIG);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EFBIG
#ifdef ENOSPC
    expected = "No space left on device";
    actual = strerror(ENOSPC);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOSPC
#ifdef ESPIPE
    expected = "Illegal seek";
    actual = strerror(ESPIPE);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ESPIPE
#ifdef EROFS
    expected = "Read-only file system";
    actual = strerror(EROFS);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EROFS
#ifdef EMLINK
    expected = "Too many links";
    actual = strerror(EMLINK);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EMLINK
#ifdef EPIPE
    expected = "Broken pipe";
    actual = strerror(EPIPE);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EPIPE
#ifdef EDOM
    expected = "Numerical argument out of domain";
    actual = strerror(EDOM);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EDOM
#ifdef ERANGE
    expected = "Numerical result out of range";
    actual = strerror(ERANGE);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ERANGE
#ifdef EDEADLK
    expected = "Resource deadlock avoided";
    actual = strerror(EDEADLK);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EDEADLK
#ifdef ENAMETOOLONG
    expected = "File name too long";
    actual = strerror(ENAMETOOLONG);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENAMETOOLONG
#ifdef ENOLCK
    expected = "No locks available";
    actual = strerror(ENOLCK);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOLCK
#ifdef ENOSYS
    expected = "Function not implemented";
    actual = strerror(ENOSYS);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOSYS
#ifdef ENOTEMPTY
    expected = "Directory not empty";
    actual = strerror(ENOTEMPTY);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOTEMPTY
#ifdef ELOOP
    expected = "Too many levels of symbolic links";
    actual = strerror(ELOOP);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ELOOP
#ifdef EWOULDBLOCK
    expected = "Resource temporarily unavailable";
    actual = strerror(EWOULDBLOCK);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EWOULDBLOCK
#ifdef ENOMSG
    expected = "No message of desired type";
    actual = strerror(ENOMSG);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOMSG
#ifdef EIDRM
    expected = "Identifier removed";
    actual = strerror(EIDRM);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EIDRM
#ifdef ECHRNG
    expected = "Channel number out of range";
    actual = strerror(ECHRNG);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ECHRNG
#ifdef EL2NSYNC
    expected = "Level 2 not synchronized";
    actual = strerror(EL2NSYNC);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EL2NSYNC
#ifdef EL3HLT
    expected = "Level 3 halted";
    actual = strerror(EL3HLT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EL3HLT
#ifdef EL3RST
    expected = "Level 3 reset";
    actual = strerror(EL3RST);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EL3RST
#ifdef ELNRNG
    expected = "Link number out of range";
    actual = strerror(ELNRNG);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ELNRNG
#ifdef EUNATCH
    expected = "Protocol driver not attached";
    actual = strerror(EUNATCH);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EUNATCH
#ifdef ENOCSI
    expected = "No CSI structure available";
    actual = strerror(ENOCSI);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOCSI
#ifdef EL2HLT
    expected = "Level 2 halted";
    actual = strerror(EL2HLT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EL2HLT
#ifdef EBADE
    expected = "Invalid exchange";
    actual = strerror(EBADE);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EBADE
#ifdef EBADR
    expected = "Invalid request descriptor";
    actual = strerror(EBADR);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EBADR
#ifdef EXFULL
    expected = "Exchange full";
    actual = strerror(EXFULL);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EXFULL
#ifdef ENOANO
    expected = "No anode";
    actual = strerror(ENOANO);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOANO
#ifdef EBADRQC
    expected = "Invalid request code";
    actual = strerror(EBADRQC);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EBADRQC
#ifdef EBADSLT
    expected = "Invalid slot";
    actual = strerror(EBADSLT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EBADSLT
#ifdef EDEADLOCK
    expected = "Resource deadlock avoided";
    actual = strerror(EDEADLOCK);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EDEADLOCK
#ifdef EBFONT
    expected = "Bad font file format";
    actual = strerror(EBFONT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EBFONT
#ifdef ENOSTR
    expected = "Device not a stream";
    actual = strerror(ENOSTR);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOSTR
#ifdef ENODATA
    expected = "No data available";
    actual = strerror(ENODATA);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENODATA
#ifdef ETIME
    expected = "Timer expired";
    actual = strerror(ETIME);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ETIME
#ifdef ENOSR
    expected = "Out of streams resources";
    actual = strerror(ENOSR);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOSR
#ifdef ENONET
    expected = "Machine is not on the network";
    actual = strerror(ENONET);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENONET
#ifdef ENOPKG
    expected = "Package not installed";
    actual = strerror(ENOPKG);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOPKG
#ifdef EREMOTE
    expected = "Object is remote";
    actual = strerror(EREMOTE);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EREMOTE
#ifdef ENOLINK
    expected = "Link has been severed";
    actual = strerror(ENOLINK);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOLINK
#ifdef EADV
    expected = "Advertise error";
    actual = strerror(EADV);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EADV
#ifdef ESRMNT
    expected = "Srmount error";
    actual = strerror(ESRMNT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ESRMNT
#ifdef ECOMM
    expected = "Communication error on send";
    actual = strerror(ECOMM);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ECOMM
#ifdef EPROTO
    expected = "Protocol error";
    actual = strerror(EPROTO);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EPROTO
#ifdef EMULTIHOP
    expected = "Multihop attempted";
    actual = strerror(EMULTIHOP);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EMULTIHOP
#ifdef EDOTDOT
    expected = "RFS specific error";
    actual = strerror(EDOTDOT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EDOTDOT
#ifdef EBADMSG
    expected = "Bad message";
    actual = strerror(EBADMSG);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EBADMSG
#ifdef EOVERFLOW
    expected = "Value too large for defined data type";
    actual = strerror(EOVERFLOW);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EOVERFLOW
#ifdef ENOTUNIQ
    expected = "Name not unique on network";
    actual = strerror(ENOTUNIQ);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOTUNIQ
#ifdef EBADFD
    expected = "File descriptor in bad state";
    actual = strerror(EBADFD);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EBADFD
#ifdef EREMCHG
    expected = "Remote address changed";
    actual = strerror(EREMCHG);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EREMCHG
#ifdef ELIBACC
    expected = "Can not access a needed shared library";
    actual = strerror(ELIBACC);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ELIBACC
#ifdef ELIBBAD
    expected = "Accessing a corrupted shared library";
    actual = strerror(ELIBBAD);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ELIBBAD
#ifdef ELIBSCN
    expected = ".lib section in a.out corrupted";
    actual = strerror(ELIBSCN);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ELIBSCN
#ifdef ELIBMAX
    expected = "Attempting to link in too many shared libraries";
    actual = strerror(ELIBMAX);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ELIBMAX
#ifdef ELIBEXEC
    expected = "Cannot exec a shared library directly";
    actual = strerror(ELIBEXEC);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ELIBEXEC
#ifdef EILSEQ
    expected = "Invalid or incomplete multibyte or wide character";
    actual = strerror(EILSEQ);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EILSEQ
#ifdef ERESTART
    expected = "Interrupted system call should be restarted";
    actual = strerror(ERESTART);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ERESTART
#ifdef ESTRPIPE
    expected = "Streams pipe error";
    actual = strerror(ESTRPIPE);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ESTRPIPE
#ifdef EUSERS
    expected = "Too many users";
    actual = strerror(EUSERS);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EUSERS
#ifdef ENOTSOCK
    expected = "Socket operation on non-socket";
    actual = strerror(ENOTSOCK);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOTSOCK
#ifdef EDESTADDRREQ
    expected = "Destination address required";
    actual = strerror(EDESTADDRREQ);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EDESTADDRREQ
#ifdef EMSGSIZE
    expected = "Message too long";
    actual = strerror(EMSGSIZE);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EMSGSIZE
#ifdef EPROTOTYPE
    expected = "Protocol wrong type for socket";
    actual = strerror(EPROTOTYPE);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EPROTOTYPE
#ifdef ENOPROTOOPT
    expected = "Protocol not available";
    actual = strerror(ENOPROTOOPT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOPROTOOPT
#ifdef EPROTONOSUPPORT
    expected = "Protocol not supported";
    actual = strerror(EPROTONOSUPPORT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EPROTONOSUPPORT
#ifdef ESOCKTNOSUPPORT
    expected = "Socket type not supported";
    actual = strerror(ESOCKTNOSUPPORT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ESOCKTNOSUPPORT
#ifdef EOPNOTSUPP
    expected = "Operation not supported";
    actual = strerror(EOPNOTSUPP);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EOPNOTSUPP
#ifdef EPFNOSUPPORT
    expected = "Protocol family not supported";
    actual = strerror(EPFNOSUPPORT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EPFNOSUPPORT
#ifdef EAFNOSUPPORT
    expected = "Address family not supported by protocol";
    actual = strerror(EAFNOSUPPORT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EAFNOSUPPORT
#ifdef EADDRINUSE
    expected = "Address already in use";
    actual = strerror(EADDRINUSE);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EADDRINUSE
#ifdef EADDRNOTAVAIL
    expected = "Cannot assign requested address";
    actual = strerror(EADDRNOTAVAIL);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EADDRNOTAVAIL
#ifdef ENETDOWN
    expected = "Network is down";
    actual = strerror(ENETDOWN);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENETDOWN
#ifdef ENETUNREACH
    expected = "Network is unreachable";
    actual = strerror(ENETUNREACH);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENETUNREACH
#ifdef ENETRESET
    expected = "Network dropped connection on reset";
    actual = strerror(ENETRESET);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENETRESET
#ifdef ECONNABORTED
    expected = "Software caused connection abort";
    actual = strerror(ECONNABORTED);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ECONNABORTED
#ifdef ECONNRESET
    expected = "Connection reset by peer";
    actual = strerror(ECONNRESET);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ECONNRESET
#ifdef ENOBUFS
    expected = "No buffer space available";
    actual = strerror(ENOBUFS);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOBUFS
#ifdef EISCONN
    expected = "Transport endpoint is already connected";
    actual = strerror(EISCONN);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EISCONN
#ifdef ENOTCONN
    expected = "Transport endpoint is not connected";
    actual = strerror(ENOTCONN);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOTCONN
#ifdef ESHUTDOWN
    expected = "Cannot send after transport endpoint shutdown";
    actual = strerror(ESHUTDOWN);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ESHUTDOWN
#ifdef ETOOMANYREFS
    expected = "Too many references: cannot splice";
    actual = strerror(ETOOMANYREFS);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ETOOMANYREFS
#ifdef ETIMEDOUT
    expected = "Connection timed out";
    actual = strerror(ETIMEDOUT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ETIMEDOUT
#ifdef ECONNREFUSED
    expected = "Connection refused";
    actual = strerror(ECONNREFUSED);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ECONNREFUSED
#ifdef EHOSTDOWN
    expected = "Host is down";
    actual = strerror(EHOSTDOWN);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EHOSTDOWN
#ifdef EHOSTUNREACH
    expected = "No route to host";
    actual = strerror(EHOSTUNREACH);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EHOSTUNREACH
#ifdef EALREADY
    expected = "Operation already in progress";
    actual = strerror(EALREADY);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EALREADY
#ifdef EINPROGRESS
    expected = "Operation now in progress";
    actual = strerror(EINPROGRESS);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EINPROGRESS
#ifdef ESTALE
    expected = "Stale file handle";
    actual = strerror(ESTALE);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ESTALE
#ifdef EUCLEAN
    expected = "Structure needs cleaning";
    actual = strerror(EUCLEAN);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EUCLEAN
#ifdef ENOTNAM
    expected = "Not a XENIX named type file";
    actual = strerror(ENOTNAM);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOTNAM
#ifdef ENAVAIL
    expected = "No XENIX semaphores available";
    actual = strerror(ENAVAIL);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENAVAIL
#ifdef EISNAM
    expected = "Is a named type file";
    actual = strerror(EISNAM);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EISNAM
#ifdef EREMOTEIO
    expected = "Remote I/O error";
    actual = strerror(EREMOTEIO);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EREMOTEIO
#ifdef EDQUOT
    expected = "Disk quota exceeded";
    actual = strerror(EDQUOT);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EDQUOT
#ifdef ENOMEDIUM
    expected = "No medium found";
    actual = strerror(ENOMEDIUM);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOMEDIUM
#ifdef EMEDIUMTYPE
    expected = "Wrong medium type";
    actual = strerror(EMEDIUMTYPE);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EMEDIUMTYPE
#ifdef ECANCELED
    expected = "Operation canceled";
    actual = strerror(ECANCELED);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ECANCELED
#ifdef ENOKEY
    expected = "Required key not available";
    actual = strerror(ENOKEY);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOKEY
#ifdef EKEYEXPIRED
    expected = "Key has expired";
    actual = strerror(EKEYEXPIRED);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EKEYEXPIRED
#ifdef EKEYREVOKED
    expected = "Key has been revoked";
    actual = strerror(EKEYREVOKED);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EKEYREVOKED
#ifdef EKEYREJECTED
    expected = "Key was rejected by service";
    actual = strerror(EKEYREJECTED);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EKEYREJECTED
#ifdef EOWNERDEAD
    expected = "Owner died";
    actual = strerror(EOWNERDEAD);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EOWNERDEAD
#ifdef ENOTRECOVERABLE
    expected = "State not recoverable";
    actual = strerror(ENOTRECOVERABLE);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOTRECOVERABLE
#ifdef ERFKILL
    expected = "Operation not possible due to RF-kill";
    actual = strerror(ERFKILL);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ERFKILL
#ifdef EHWPOISON
    expected = "Memory page has hardware error";
    actual = strerror(EHWPOISON);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //EHWPOISON
#ifdef ENOTSUP
    expected = "Operation not supported";
    actual = strerror(ENOTSUP);
    if(strcmp(expected, actual)) {
        exit(1);
    }
#endif //ENOTSUP
    return *good;
}
