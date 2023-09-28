import os
import subprocess
import threading
import time

class FilterThread(threading.Thread):
    def __init__(self, threadID, input_proc, file_path, delay, container_id):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.Popen = input_proc
        self.file_path = file_path
        self.delay = delay
        self.container_id = container_id
    def run(self):
        start = int(time.time())
        result = ""
        text_reader = open(self.file_path, "r")
        while True:
            line = text_reader.readline()
            if len(line) > 0:
                print(line.strip())
            else:
                if int(time.time()) - start > self.delay:
                    result = "[Timeout] The time of analysis is out!"
                    print("[Timeout] The time of analysis is out!")
                    break
                if self.Popen.poll() != None:
                    result = "[Finish] The analysis process finished successfully."
                    print("[Finish] The analysis process finished successfully.")
                    break
                time.sleep(1)
        text_reader.close()

        # Finish the analyzing!
        self.Popen.kill()
        os.system("sudo docker stop " + self.container_id)
        os.system("sudo docker rm " + self.container_id)
        print("The analyzing has finished.")
        end = int(time.time())
        total_time = end - start
        with open(self.file_path, "a") as f:
            f.write(result+"\n")
            f.write("\nTime Consuming: {0} seconds.\n".format(total_time))


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
docker_firmware_dir = "/home/satc/SaTC/firmware"
docker_result_dir = "/home/satc/SaTC/output"

def run_satc(firmware_dir, result_dir, binary=None):

    if not os.path.exists(result_dir):
        os.mkdir(result_dir)

    run_cmd = "sudo docker run -itd -v {0}:{1} -v {2}:{3} huangpayoung/satc:V3.0".format(firmware_dir, docker_firmware_dir, result_dir, docker_result_dir)
    print(run_cmd)
    f = os.popen(run_cmd)
    container_id = f.read()
    container_id = container_id.strip()
    print("container_id=" + container_id)
    print("Run docker container succeed!")

    # "docker exec"
    print("Start change mod!")
    chmod_cmd = 'chmod -R 777 /home/satc/SaTC/output/'
    os.system("sudo docker exec -it -u root {0} /bin/bash -c \'{1}\'".format(container_id, chmod_cmd))
    # Add permissions.
    chmod_cmd = 'chmod -R a+r /home/satc/SaTC/firmware/'
    os.system("sudo docker exec -it -u root {0} /bin/bash -c \'{1}\'".format(container_id, chmod_cmd))
    chmod_cmd = 'chmod -R a+w /home/satc/SaTC/firmware/'
    os.system("sudo docker exec -it -u root {0} /bin/bash -c \'{1}\'".format(container_id, chmod_cmd))
    print("Change mod done!")

    # New scripts.
    ghidra_script = "--ghidra_script ref2share --ghidra_script share2sink --ghidra_script ref2sink_cmdi --ghidra_script ref2sink_bof"
    # ghidra_script = "--ghidra_script call2sink"
    exec_cmd2 = "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && mkvirtualenv SaTC && \
    python /home/satc/SaTC/satc.py -d /home/satc/SaTC/firmware -o /home/satc/SaTC/output {0}".format(ghidra_script)
    # Manually specification
    exec_cmd2 += " --save_ghidra_project "
    exec_cmd2 += " --taint_check "
    if binary is not None:
        exec_cmd2 += " -b " + binary
    print("Start satc exec!")
    satc_log_path = os.path.join(result_dir, "satc_log")
    satc_log = open(satc_log_path, "w+")
    proc = subprocess.Popen("sudo docker exec -it -u satc {0} /bin/bash -c \'{1}\'".format(container_id, exec_cmd2), 
    shell=True, stdout=satc_log)

    # Set time limit to be 96 hours
    # thread_id, popen, log_file_path, delay_seconds
    delay_seconds = 3600 * 24 * 4
    thread1 = FilterThread(1, proc, satc_log_path, delay_seconds, container_id)
    thread1.start()

    print("Return from run_satc.")
    return container_id


def run_satc_v2():
    firms = [
        "US_AC18_kf_V15.03.05.19_6318_cn.bin",
        "DIR-878_A1_FW130B08_Beta_20220412_Decode.img",
        "R6400-V1.0.1.70_1.0.44.chk",
        "R7000P-V1.3.3.140_10.1.75.chk",
    ]
    for firmware in firms:
        print("Analyzing {0}".format(firmware))
        firmware_dir = os.path.join(BASE_DIR, "_" + firmware + ".extracted")
        result_dir = os.path.join(BASE_DIR, "result_" + firmware)
        container_id = run_satc(firmware_dir, result_dir)

if __name__ == '__main__':
    run_satc_v2()
