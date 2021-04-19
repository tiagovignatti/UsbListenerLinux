#include <unistd.h>
#include <poll.h>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <sys/signalfd.h>
#include <csignal>
#include <libudev.h>
#include <string.h>

using namespace std;

void scanDevices(struct udev *udev) {
    struct udev_device *device;
    struct udev_enumerate *enumerate;
    struct udev_list_entry *devices, *dev_list_entry;

    // Create enumerate object
    enumerate = udev_enumerate_new(udev);
    if (!enumerate) {
        printf("Error while creating udev enumerate\n");
        return;
    }

    // Scan devices
    udev_enumerate_scan_devices(enumerate);

    // Fill up device list
    devices = udev_enumerate_get_list_entry(enumerate);
    if (!devices) {
        printf("Error while getting device list\n");
        return;
    }

    udev_list_entry_foreach(dev_list_entry, devices) {
        // Get the device
        device = udev_device_new_from_syspath(udev, udev_list_entry_get_name(dev_list_entry));
        if (udev_device_get_devtype(device) &&
            (udev_device_get_property_value(device, "ID_SERIAL_SHORT") != NULL) &&
            !strcmp(udev_device_get_devtype(device), "usb_device")) {
            std::string devpath(udev_device_get_devpath(device));
            std::string devserialshort(udev_device_get_property_value(device, "ID_SERIAL_SHORT"));
            cout << "Scanned: " << devpath + "#" + devserialshort << endl;
        }

        // Free the device
        udev_device_unref(device);
    }
    // Free enumerate
    udev_enumerate_unref(enumerate);
}

void monitorDevices(int signal_fd, struct udev *udev) {
    udev_monitor *monitor = udev_monitor_new_from_netlink(udev, "udev");
    struct pollfd pfd[2];
    int ret_poll;
    ssize_t  n;

    // Enable receiving hotplug events
    udev_monitor_enable_receiving(monitor);

    pfd[0].events = POLLIN;
    pfd[0].fd = signal_fd;
    pfd[1].events = POLLIN;
    pfd[1].fd = udev_monitor_get_fd(monitor);
    if (pfd[1].fd < 0) {
        printf("Error while getting hotplug monitor\n");
        udev_monitor_unref(monitor);
        return;
    }

    while (true) {
        // Wait for events without time limit
        ret_poll = poll(pfd, 2, -1);
        if (ret_poll < 0) {
            printf("Error while polling file descriptors\n");
            break;
        }
        // True, if a signal from the operating system was sent to this process
        if (pfd[0].revents & POLLIN) {
            struct signalfd_siginfo signal_info;
            // Get the signal
            n = read(pfd[0].fd, &signal_info, sizeof(signal_info));
            // True, if an error occurred while getting the signal
            if (n == -1) {
                printf("Error while read on signal file descriptor\n");
                break;
            }
            // Check which signal was caught
            switch (signal_info.ssi_signo) {
                case SIGINT:
                    printf("SIGINT received\n");
                    break;

                case SIGTERM:
                    printf("SIGTERM received\n");
                    break;

                default:
                    printf("Unknown signal received\n");
            }
            break;
        }
        if (pfd[1].revents & POLLIN) {
            // Get the device
            struct udev_device *device = udev_monitor_receive_device(monitor);
            if (!device) {
                printf("Error while getting device...returning to work\n");
                continue;
            }

            if (udev_device_get_devtype(device) &&
                !strcmp(udev_device_get_devtype(device), "usb_device"))
            {
                if (!strcmp(udev_device_get_action(device), "add")) {
                    std::string devpath(udev_device_get_devpath(device));
                    std::string devserialshort(udev_device_get_property_value(device, "ID_SERIAL_SHORT"));
                    cout << "Monitored: " << devpath + "#" + devserialshort << " ACTION: " << udev_device_get_action(device) << endl;
                }
                else if (!strcmp(udev_device_get_action(device), "remove")) {
                    std::string devpath(udev_device_get_devpath(device));
                    cout << "Monitored: " << devpath << " ACTION: " << udev_device_get_action(device) << endl;
                }
            }

            // Free the device
            udev_device_unref(device);
        }
    }
    // Free the monitor
    udev_monitor_unref(monitor);
}

int main() {
    // Create a new udev object
    struct udev *udev = udev_new();
    if (!udev) {
        printf("Error while initialization!\n");
        return EXIT_FAILURE;
    }

    sigset_t mask;

    // Set signals we want to catch
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);

    // Change the signal mask and check
    if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) {
        fprintf(stderr, "Error while sigprocmask(): %s\n", std::strerror(errno));
        return EXIT_FAILURE;
    }
    // Get a signal file descriptor
    int signal_fd = signalfd(-1, &mask, 0);
    // Check the signal file descriptor
    if (signal_fd < 0) {
        fprintf(stderr, "Error while signalfd(): %s\n", std::strerror(errno));
        return EXIT_FAILURE;
    }
    // First scan already attached devices
    scanDevices(udev);
    // Second monitor hotplug events
    monitorDevices(signal_fd, udev);
    // Free the udev object
    udev_unref(udev);
}
