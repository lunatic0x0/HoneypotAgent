#!/usr/bin/python3
import os
import sys
import subprocess
import collections
import time
import mmap
import json
import mysql.connector
LOG_FILE = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

def database_init():
    try:
        honeypot_db = mysql.connector.connect(host="192.168.0.104", user="root", password="Crisann345", database = "honeypot_data")
    except Exception as e:
        print(e)

    return honeypot_db

#table names
CMDLINE_INPUT =  "cmdline_input"
CONNECTIONS = 'connections'
FILE_DOWNLOAD = 'file_download'
LOGIN_ATTEMPT = 'login_attempt'

def send_data_to_database(data_list, data_type):
    try:
        honeypot_db = database_init()
        if honeypot_db:
            hp_cursor = honeypot_db.cursor()
            if data_type == CONNECTIONS:
                sql_query = """INSERT INTO {} VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""".format(data_type)
                query_values = (data_list[0], data_list[1], int(data_list[2]), data_list[3], int(data_list[4]), data_list[5], data_list[6], data_list[7], data_list[8], data_list[9], float(data_list[10]))
            if data_type == LOGIN_ATTEMPT:
                sql_query = """INSERT INTO {} VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""".format(data_type)
                query_values = (data_list[0], data_list[1], data_list[2], data_list[3], data_list[4], data_list[5], data_list[6], data_list[7])
            
            hp_cursor.execute(sql_query, query_values)
            honeypot_db.commit()
            print("Successfully inserted data.. !!!")
    except Exception as e:
        print(e)
       
def correct_timestamp(tmp):
    date = tmp.split("T")[0]
    time = tmp.split("T")[1][:-1]
    tstamp = date + " " + time
    return tstamp


def parseLogLines(line):
    data = json.loads(line)
    if data['eventid'] == "cowrie.session.connect":
        print("Got connection!!!")
        tstamp = correct_timestamp(data['timestamp'])
        data_list = [data['eventid'], data['src_ip'], data['src_port'], data['dst_ip'], data['dst_port'], data['session'], data['protocol'], data['message'], data['sensor'], tstamp, 0]
        send_data_to_database(data_list, CONNECTIONS)

    if data['eventid'] == "cowrie.session.closed":
        print("Session Closed!!!")
        tstamp = correct_timestamp(data['timestamp'])
        data_list = [data['eventid'], data['src_ip'], NULL, NULL, NULL, data['session'], NULL, data['message'], data['sensor'], tstamp, data['duration']]
        send_data_to_database(data_list, CONNECTIONS)

    if data['eventid'] == "cowrie.login.failed":
        print("Failed Login Attempt!!!")
        tstamp = correct_timestamp(data['timestamp'])
        data_list = [data['eventid'], data['username'], data['password'], data['message'], data['sensor'], tstamp, data['src_ip'], data['session']]    
        send_data_to_database(data_list, LOGIN_ATTEMPT)
    
    if data['eventid'] == "cowrie.login.success":
        print("Successful Login Attempt!!!")
        tstamp = correct_timestamp(data['timestamp'])
        data_list = [data['eventid'], data['username'], data['password'], data['message'], data['sensor'], tstamp, data['src_ip'], data['session']]
        send_data_to_database(data_list, LOGIN_ATTEMPT)

    


def tail(file, lnum):
    with open(file, "r") as f:
        lines = f.readlines()
        arr = lines[lnum:]
        file_num = 0
        for l in lines:
            file_num = file_num + 1

    return arr, file_num


def main():
    print('Watching ' + LOG_FILE + '. Started at ' + time.strftime('%Y-%m-%d %I:%M:%S %p'))

    mtime_last = 0
    cur_line_num = 0
    start_line_num = 0
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
        for l in lines:
            start_line_num = start_line_num + 1

    while True:
        try:
            mtime_cur = os.path.getmtime(LOG_FILE)
            if mtime_cur != mtime_last:
                lines, cur_line_num = tail(LOG_FILE, start_line_num)
                for i in lines:
                    #
                    parseLogLines(i)
            mtime_last = mtime_cur
            start_line_num = cur_line_num
            time.sleep(5)
        except KeyboardInterrupt:
            exit(-1)
        except Exception as e:
            continue

if __name__ == "__main__":
    main()
