from datetime import date
from django.forms import DateInput
from django.shortcuts import render
from django.views.generic import TemplateView
from .models import Honey
from rest_framework.views import APIView
from rest_framework.response import Response
import pandas as pd
import mysql.connector


# Create your views here.
def database_init():
    try:
        honeypot_db = mysql.connector.connect(host="192.168.0.104", user="root", password="Crisann345", database = "honeypot_data")
    except Exception as e:
        print(e)

    return honeypot_db

class HoneyChartView(TemplateView):
    template_name = 'honey/chart.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["qs"] = Honey.objects.all()
        return context

class SourceIpChartView(APIView):

    def post(self, request, format=None):
        honeypot_db = database_init()
        date_input = request.data['hp_time']
        print(date_input)
        df = pd.read_sql_query("SELECT src_ip, count(*) AS ip_count FROM honeypot_data.connections WHERE timestamp > '{} 00:00:00.0000' GROUP BY src_ip ORDER BY count(*) desc limit 10".format(date_input), honeypot_db)
        print(df)
        ip_label = df.src_ip
        ip_count = df.ip_count
        data = {
            "ip_label" : ip_label,
            "ip_count" : ip_count
        } 
        honeypot_db.close()
        return Response(data)    

class TotalAttacksChartView(APIView):
    def post(self, request, format=None):
        honeypot_db = database_init()
        date_input = request.data['hp_time']
        print(date_input)
        df = pd.read_sql_query("select src_ip, count(*) AS totalattacks From honeypot_data.connections where timestamp > '{} 00:00:00.0000' UNION select src_ip, count(*) AS totalattacks From honeypot_data.login_attempt where timestamp > '{} 00:00:00.0000'".format(date_input,date_input), honeypot_db)
        if len(df) != 0:
            total_attack = []
            for i in range(len(df)):
                total_attack.append(df.loc[i, "totalattacks"])

        total_attack_count = 0
        for i in total_attack:
            total_attack_count = total_attack_count + int(i)

        ip_df = pd.read_sql_query("SELECT src_ip, count(*) AS ip_count FROM honeypot_data.connections WHERE timestamp > '{} 00:00:00.0000' GROUP BY src_ip ORDER BY count(*) desc".format(date_input), honeypot_db)
        if len(ip_df) != 0:
            unique_ip_count = 0
            j = 1
            for i in range(len(ip_df)):
                unique_ip_count = unique_ip_count + j
                j = j + 1

        print("Total Attack Count:", total_attack_count)
        print("Unique IP Count:", unique_ip_count)
        data = {
            "total_attack_count" : total_attack_count,
            "unique_ip_count" : unique_ip_count
        }

        honeypot_db.close()
        return Response(data)
            
class UserChartView(APIView):
    def post(self, request, format=None):
        date_input = request.data['hp_time']
        honeypot_db = database_init()
        df = pd.read_sql_query("SELECT username, count(*) AS ucount FROM honeypot_data.login_attempt where timestamp > '{} 00:00:00.0000' GROUP BY username ORDER BY count(*) DESC limit 10".format(date_input), honeypot_db)
        print(df)
        user_name = df.username
        user_count = df.ucount
        data = {
            "usernames" : user_name,
            "username_counts" : user_count,
        } 
        honeypot_db.close()
        return Response(data)

class PassChartView(APIView):
    def post(self, request, format=None):
        date_input = request.data['hp_time']
        honeypot_db = database_init()
        df = pd.read_sql_query("SELECT password, count(*) AS pcount FROM honeypot_data.login_attempt where timestamp > '{} 00:00:00.0000' GROUP BY password ORDER BY count(*) DESC limit 10".format(date_input), honeypot_db)
        print(df)
        user_pass = df.password
        pass_count = df.pcount
        data = {
            "passwords" : user_pass,
            "password_counts" : pass_count,
        } 
        honeypot_db.close()
        #return render(request, "chart.html", {"data" : data})
        return Response(data)
