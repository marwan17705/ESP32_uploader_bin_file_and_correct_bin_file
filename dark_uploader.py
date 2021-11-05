import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import os
import hashlib
import sys
from tkinter.scrolledtext import ScrolledText
from subprocess import Popen, PIPE
from threading import Thread, Lock
import time 
root = tk.Tk()
root.title("INET IoT HATYAI uploader")
root.resizable(False, False)
root.geometry("500x500")

comport_= ''
filename_= ''








def get_checksum(filename, hash_function):
    """Generate checksum for file baed on hash function (MD5 or SHA256).

    Args:
        filename (str): Path to file that will have the checksum generated.
        hash_function (str):  Hash function name - supports MD5 or SHA256
 
    Returns:
        str`: Checksum based on Hash function of choice.
 
    Raises:
        Exception: Invalid hash function is entered.
    """
    hash_function = hash_function.lower()
 
    with open(filename, "rb") as f:
        bytes = f.read()  # read file as bytes
        if hash_function == "md5":
            readable_hash = hashlib.md5(bytes).hexdigest()
        elif hash_function == "sha256":
            readable_hash = hashlib.sha256(bytes).hexdigest()
        else:
            Raise("{} is an invalid hash function. Please Enter MD5 or SHA256")
 
    return readable_hash
def upload_fmw(comport,f_name):
    #f_name = input("Please enter your path/firmware?")
    #comport = input("Please enter COMPORT?")

    #comport = 'COM11'
    #f_name = "fmw/test.bin"

    file = open(f_name, "rb")
    byte = file.read(1)
    byte_str =[]
    while byte:
        #byte_str.append((ord(byte)))
        byte_str.append(byte)
        byte = file.read(1)
        
    file.close()
    #print(byte_str)
    #print(len(byte_str))
    #print(hex(calculate(byte_str)))
    os.system('echo %cd%')
    print(f_name.split(sep='/'))
    old_file = f_name.split(sep='/')
    path= ''
    for index, slash in enumerate(old_file):
        if(index == len(old_file)-1):
            break;
        path+=slash + '/'
    print(path)
    #f_name_edit = "valid_" + old_file[len(old_file)-1]
    f_name_edit = path + "valid_" + old_file[len(old_file)-1]

    application_path = os.path.dirname(sys.executable)
    print('this path is '+application_path)
    #C:/Users/USER/Desktop/dark_fmw/fmw/test.bin
    
    c_edit = 1; 
    while(os.path.isfile(f_name_edit)):
        f_name_edit = path + "valid"+str(c_edit)+"_" + old_file[len(old_file)-1]
        #f_name_edit = "valid"+str(c_edit)+"_" + old_file[len(old_file)-1]
        c_edit+=1
    print(os.path.isfile(f_name_edit))
    edit_file = open(f_name_edit, 'wb')
    #print('Ceate new firmware : '+f_name_edit)
    run_command_in_entry('echo Ceate new firmware : '+f_name_edit)

    #res_cmd = os.system("esptool.exe --chip esp32 image_info D:\\test\\py_test\\"+f_name)
    res_cmd =os.popen("esptool.exe --chip esp32 image_info "+f_name).read()

    #os.system("dir")
    
    #print(res_cmd)
    i_check = res_cmd.index('Checksum')
    #print(i_check)    
    checksum_info= ''
    for index, item in enumerate(res_cmd):
        if(index >= i_check): 
            #print(index, item)
            checksum_info+=item
            if(item== '\0'):
                break;
    valid_checksum=0
    #print(checksum_info)

    if '(invalid'in (checksum_info):
        i_check = res_cmd.index('calculated')
        valid_checksum =  int(res_cmd[i_check+len('calculated')+1]+ res_cmd[i_check+len('calculated')+2],16)
        #print('invalid');
        #print(hex(valid_checksum));

    elif '(valid'in (checksum_info):
        i_check = res_cmd.index('Checksum:')
        #print('valid');
        valid_checksum =  int(res_cmd[i_check+len('Checksum:')+1]+ res_cmd[i_check+len('Checksum:')+2],16)
        #print(hex(valid_checksum));


    line_edit_file=0
    for index_byte in byte_str:
        if(line_edit_file+33 >= len(byte_str)):
            #print('finish ')
            edit_file.write(valid_checksum.to_bytes(1, 'little'))
            break
        line_edit_file+=1
        edit_file.write(index_byte)

    edit_file.close()

    sha256_result = get_checksum(f_name_edit, "sha256")
    #print('Hash Function: SHA256 : {}'.format(sha256_result),type(sha256_result))

    sha256_byte = []

    edit_file = open(f_name_edit, 'ab')
    for index, item in enumerate(sha256_result):
        if(index%2==0):
            sha256_byte.append(int(sha256_result[index],16)*16)
        else:
            sha256_byte[int(index/2)]+= int(sha256_result[index],16)
            edit_file.write(sha256_byte[int(index/2)].to_bytes(1, 'little'))
    edit_file.close()

    #print(f_name_edit)
    os.system("esptool.exe --chip esp32 image_info "+f_name_edit)
    #os.system("esptool.exe --chip esp32 --port "+comport+" --baud 921600 --before default_reset --after hard_reset write_flash -z --flash_mode dio --flash_freq 80m --flash_size detect 0x10000 "+f_name_edit)
    #res_cmd =os.popen("esptool.exe --chip esp32 --port "+comport+" --baud 921600 --before default_reset --after hard_reset write_flash -z --flash_mode dio --flash_freq 80m --flash_size detect 0x10000 "+f_name_edit).read()
    #tk.Label(root, text=res_cmd, bg = "white",width=65,height=20).place(x=250, y= 300, anchor='center')
    #run_command_in_entry("esptool.exe --chip esp32 image_info "+f_name_edit)
    
    run_command_in_entry("esptool.exe --chip esp32 --port "+comport+" --baud 921600 --before default_reset --after hard_reset write_flash -z --flash_mode dio --flash_freq 80m --flash_size detect 0x10000 "+f_name_edit)

    
def UploadAction_file(event=None):
    filename = filedialog.askopenfilename()
    global filename_ 
    filename_= filename
    #print('Selected:', filename)
    tk.Label(root, text=filename, bg = "white",width=40,height=1).place(x=170, y= 20, anchor='nw')
    #print(filename_)

def callbackFunc(event):
    print('Selected:', event.widget.get())
    comport=''
    for char in event.widget.get():
        if(char=='='):
            break
        comport+=char
    global comport_ 
    comport_= comport
    #print(comport_)
    tk.Label(root, text=comport, bg = "white",width=40,height=1).place(x=170, y= 60, anchor='nw')
    
def callSummit(event):
    print('press')
    print(comport_)
    print(filename_)
    upload_fmw(comport_,filename_);
    
    
def run_command_in_entry(cmd):
    #console.run(entry.get())
    console.run(cmd)
    #entry.delete("0", "end")
    return "break"
    
class Console(ScrolledText):

    def __init__(self, master, **kwargs):
        # The default options:
        text_options = {"state": "disabled",
                        "bg": "black",
                        "fg": "#08c614",
                        "selectbackground": "orange",
                        "width":55,
                        "height":20
                        }
        # Take in to account the caller's specified options:
        text_options.update(kwargs)
        super().__init__(master, **text_options)

        self.proc = None # The process
        self.text_to_show = "" # The new text that we need to display on the screen
        self.text_to_show_lock = Lock() # A lock to make sure that it's thread safe

        self.show_text_loop()

    def clear(self) -> None:
        """
        Clears the Text widget
        """
        super().config(state="normal")
        super().delete("0.0", "end")
        super().config(state="disabled")

    def show_text_loop(self) -> None:
        """
        Inserts the new text into the `ScrolledText` wiget
        """
        new_text = ""
        # Get the new text that needs to be displayed
        with self.text_to_show_lock:
            new_text = self.text_to_show.replace("\r", "")
            self.text_to_show = ""

        if len(new_text) > 0:
            # Display the new text:
            super().config(state="normal")
            super().insert("end", new_text)
            super().see("end")
            super().config(state="disabled")

        # After 100ms call `show_text_loop` again
        super().after(10, self.show_text_loop)

    def run(self, command:str) -> None:
        """
        Runs the command specified
        """
        self.stop()
        thread = Thread(target=self._run, daemon=True, args=(command, ))
        thread.start()

    def _run(self, command:str) -> None:
        """
        Runs the command using subprocess and appends the output
        to `self.text_to_show`
        """
        self.proc = Popen(command, shell=True, stdout=PIPE)

        try:
            while self.proc.poll() is None:
                text = self.proc.stdout.read(1).decode()
                with self.text_to_show_lock:
                    self.text_to_show += text

            self.proc = None
        except AttributeError:
            # The process ended prematurely
            pass

    def stop(self, event:tk.Event=None) -> None:
        """
        Stops the process.
        """
        try:
            self.proc.kill()
            self.proc = None
        except AttributeError:
            # No process was running
            pass

    def destroy(self) -> None:
        # Stop the process if the text widget is to be destroyed:
        self.stop()
        super().destroy()




    

#grid_frame =tk.Frame(root)
#grid_frame.pack(side=tk.LEFT,)
# import firmware
tk.Button(root, text='Import firmware', command=UploadAction_file).place(x=20, y= 20, anchor='nw')
tk.Label(root, text='', bg = "white",width=40,height=1).place(x=170, y= 20, anchor='nw')
# create a combobox comport
tk.Label(root, text='', bg = "white",width=40,height=1).place(x=170, y= 60, anchor='nw')
port_cmd =os.popen("chgport").read()
os.system("chgport")
port_list=['Null']
port=''
for char in port_cmd:
    #print(char)
    if(char=='\n' and len(port) > 0):
        port_list.append(port)
        port=''
        print("add");
    else:    
        port+=char
print(port_list)
selected_port_list = tk.StringVar()
port_cb = ttk.Combobox(root, textvariable=selected_port_list)
port_cb['values'] = port_list
#month_cb['state'] = 'readonly'  # normal
port_cb.place(x=20, y= 60, anchor='nw')
port_cb.current(0)
port_cb.bind("<<ComboboxSelected>>", callbackFunc)
# summit config
b = tk.Button(root, text='upload')
b.bind("<Button-1>", callSummit)
b.place(x=20,y=100)
# output 
#tk.Label(root, text='', bg = "white",width=65,height=20).place(x=250, y= 300, anchor='center')
console = Console(root)
console.place(x=250, y= 300, anchor='center')


root.mainloop()
