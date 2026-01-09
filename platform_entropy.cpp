// platform_entropy.cpp

#include <stdexcept>
#include <span>
#include <cstddef>
#include <cstdint>
#include <string>     // for std::string in error messages
#include <cstring>    // for strerror


#if defined(_WIN32) || defined(_WIN64)
    #define NOMINMAX
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <bcrypt.h>
    #include <cerrno>     // for errno, EINTR
    #pragma comment(lib, "bcrypt.lib")
#else
    #include <unistd.h>     // for read/close
    #include <fcntl.h>      // for open
    #include <sys/syscall.h> // for syscall
    #include <linux/random.h> // for GRND_ flags (may not exist on older systems)
    #include <errno.h>
#endif


namespace RNG_platform {

    void get_entropy(unsigned char* buffer, std::size_t size)
    {
        if (size == 0) return; // or throw, depending on preference

#if defined(_WIN32) || defined(_WIN64)

        constexpr std::size_t MAX_BCRYPT_REQUEST = std::numeric_limits<ULONG>::max();

        while (size > 0) {
            // BCryptGenRandom accepts ULONG, which is 32-bit_count on 32-bit_count Windows
            // So we must chunk large requests
            ULONG chunk = static_cast<ULONG>(std::min(size, MAX_BCRYPT_REQUEST));

            // Windows: BCryptGenRandom with system-preferred RNG
            NTSTATUS status = BCryptGenRandom(
                nullptr,
                buffer,
                chunk,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG
            );
            if (!BCRYPT_SUCCESS(status))
                throw std::runtime_error("BCryptGenRandom failed");

            buffer += chunk;
            size -= chunk;
        }

#else

        // Unix-like systems: prefer getrandom(), fall back to /dev/urandom

        // First try: getrandom() syscall (modern Linux, some BSDs)
#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__)
        {
            size_t filled = 0;
            while (filled < size) {
                // GRND_NONBLOCK is not needed here — we want blocking behavior like urandom
                long ret = syscall(SYS_getrandom, buffer + filled, size - filled, 0);
                if (ret > 0) {
                    filled += static_cast<size_t>(ret);
                }
                else if (ret == 0) {
                    // Shouldn't happen with blocking, but treat as error
                    break;
                }
                else { // ret < 0
                    if (errno == EINTR) continue;
                    if (errno == ENOSYS) goto fallback_urandom; // syscall not supported
                    throw std::runtime_error("getrandom() failed: " + std::string(strerror(errno)));
                }
            }
            if (filled == size) return; // success!
        }
    fallback_urandom:
#endif

        // Fallback: /dev/urandom (works on virtually all Unix-like systems)
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd == -1)
            throw std::runtime_error("Failed to open /dev/urandom: " + std::string(strerror(errno)));

        struct Closer { int fd; ~Closer() { if (fd != -1) close(fd); } };
        Closer closer{ fd };

        size_t remaining = size;
        unsigned char* ptr = buffer;

        while (remaining > 0) {
            ssize_t ret = read(fd, ptr, remaining);
            if (ret <= 0) {
                if (ret == 0)
                    throw std::runtime_error("/dev/urandom: unexpected EOF");
                if (errno == EINTR) continue;
                throw std::runtime_error("read(/dev/urandom) failed: " + std::string(strerror(errno)));
            }
            ptr += ret;
            remaining -= ret;
        }

#endif
    }

} // namespace RNG_platform



