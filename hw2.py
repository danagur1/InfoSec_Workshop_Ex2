import sys

FW_sys_path = "/sys/class/FW_class/FW_class_FW_Device/sysfs_att"

def zero_count():
    with open(FW_sys_path, 'w') as data_file:
        data_file.write("0")

def print_FW_data():
    with open(FW_sys_path, 'r') as data_file:
        dropped = int(data_file.readline())
        accepted = int(data_file.readline())
        print("Firewall Packets Summary:\nNumber of accepted packets:"+str(accepted)+"\nNumber of dropped packets: "+str(dropped)+"\nTotal number of packets: "+str(accepted+dropped))

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_FW_data()
    elif len(sys.argv) == 2 and sys.argv[1]=="0":
        zero_count()
    else:
        print("The program can get 0 arguments or 1 arument- \"0\"")
        exit(1)
