
import pandas as pd
import numpy as np
from sklearn import preprocessing
import pickle
val=input("Enter the name of the csv file for classification: ")	
data=pd.read_csv(val)
#data.isnull().any()


#data.fillna(data.mean(), inplace=True)

data.drop(columns=['Flow.ID', 'Source.IP', 'Destination.IP', 'Protocol','Timestamp','Fwd.Packet.Length.Max', 'Fwd.Packet.Length.Min',
                  'Bwd.Packet.Length.Max', 'Bwd.Packet.Length.Min','Flow.IAT.Max','Flow.IAT.Min','Fwd.IAT.Max', 'Fwd.IAT.Min','Bwd.IAT.Max', 'Bwd.IAT.Min','Label','Bwd.Avg.Bulk.Rate','Bwd.Avg.Packets.Bulk','Bwd.Avg.Bytes.Bulk','CWE.Flag.Count','Fwd.Avg.Bytes.Bulk',
                 'Fwd.Avg.Bulk.Rate','Bwd.Avg.Bytes.Bulk','Bwd.Avg.Packets.Bulk','Fwd.Avg.Bulk.Rate','Bwd.Avg.Bulk.Rate','Fwd.URG.Flags','Bwd.PSH.Flags','Bwd.URG.Flags',
                  'FIN.Flag.Count','RST.Flag.Count','ECE.Flag.Count'],inplace=True)
                   
data.drop(columns=['Active.Max','Active.Min','Idle.Max','Idle.Min'],inplace=True)


print('Normalizing Features')
min_max_scaler = preprocessing.MinMaxScaler(feature_range=(0, 65000))
data['scale_Flow.Duration']=min_max_scaler.fit_transform(data[['Flow.Duration']])
data['scale_Total.Fwd.Packets']=min_max_scaler.fit_transform(data[['Total.Fwd.Packets']])
data['scale_Total.Backward.Packets']=min_max_scaler.fit_transform(data[['Total.Backward.Packets']])
data['scale_Total.Length.of.Fwd.Packets']=min_max_scaler.fit_transform(data[['Total.Length.of.Fwd.Packets']])
data['scale_Total.Length.of.Bwd.Packets']=min_max_scaler.fit_transform(data[['Total.Length.of.Bwd.Packets']])
data['scale_Fwd.Packet.Length.Mean']=min_max_scaler.fit_transform(data[['Fwd.Packet.Length.Mean']])
data['scale_Fwd.Packet.Length.Std']=min_max_scaler.fit_transform(data[['Fwd.Packet.Length.Std']])
data['scale_Bwd.Packet.Length.Mean']=min_max_scaler.fit_transform(data[['Bwd.Packet.Length.Mean']])
data['scale_Bwd.Packet.Length.Std']=min_max_scaler.fit_transform(data[['Bwd.Packet.Length.Std']])
data['scale_Flow.Bytes.s']=min_max_scaler.fit_transform(data[['Flow.Bytes.s']])
data['scale_Flow.Packets.s']=min_max_scaler.fit_transform(data[['Flow.Packets.s']])
data['scale_Flow.IAT.Mean']=min_max_scaler.fit_transform(data[['Flow.IAT.Mean']])
data['scale_Flow.IAT.Std']=min_max_scaler.fit_transform(data[['Flow.IAT.Std']])
data['scale_Fwd.IAT.Total']=min_max_scaler.fit_transform(data[['Fwd.IAT.Total']])
data['scale_Fwd.IAT.Mean']=min_max_scaler.fit_transform(data[['Fwd.IAT.Mean']])
data['scale_Fwd.IAT.Std']=min_max_scaler.fit_transform(data[['Fwd.IAT.Std']])
data['scale_Bwd.IAT.Total']=min_max_scaler.fit_transform(data[['Bwd.IAT.Total']])
data['scale_Bwd.IAT.Mean']=min_max_scaler.fit_transform(data[['Bwd.IAT.Mean']])
data['scale_Bwd.IAT.Std']=min_max_scaler.fit_transform(data[['Bwd.IAT.Std']])
data['scale_Fwd.Header.Length']=min_max_scaler.fit_transform(data[['Fwd.Header.Length']])
data['scale_Bwd.Header.Length']=min_max_scaler.fit_transform(data[['Bwd.Header.Length']])
data['scale_Fwd.Packets.s']=min_max_scaler.fit_transform(data[['Fwd.Packets.s']])
data['scale_Bwd.Packets.s']=min_max_scaler.fit_transform(data[['Bwd.Packets.s']])
data['scale_Packet.Length.Variance']=min_max_scaler.fit_transform(data[['Packet.Length.Variance']])
data['scale_SYN.Flag.Count']=min_max_scaler.fit_transform(data[['SYN.Flag.Count']])
data['scale_PSH.Flag.Count']=min_max_scaler.fit_transform(data[['PSH.Flag.Count']])
data['scale_ACK.Flag.Count']=min_max_scaler.fit_transform(data[['ACK.Flag.Count']])
data['scale_URG.Flag.Count']=min_max_scaler.fit_transform(data[['URG.Flag.Count']])
data['scale_Down.Up.Ratio']=min_max_scaler.fit_transform(data[['Down.Up.Ratio']])
data['scale_Average.Packet.Size']=min_max_scaler.fit_transform(data[['Average.Packet.Size']])
data['scale_Avg.Fwd.Segment.Size']=min_max_scaler.fit_transform(data[['Avg.Fwd.Segment.Size']])
data['scale_Avg.Bwd.Segment.Size']=min_max_scaler.fit_transform(data[['Avg.Bwd.Segment.Size']])
data['scale_Fwd.Avg.Packets.Bulk']=min_max_scaler.fit_transform(data[['Fwd.Avg.Packets.Bulk']])
data['scale_Subflow.Fwd.Packets']=min_max_scaler.fit_transform(data[['Subflow.Fwd.Packets']])
data['scale_Subflow.Fwd.Bytes']=min_max_scaler.fit_transform(data[['Subflow.Fwd.Bytes']])
data['scale_Subflow.Bwd.Packets']=min_max_scaler.fit_transform(data[['Subflow.Bwd.Packets']])
data['scale_Subflow.Bwd.Bytes']=min_max_scaler.fit_transform(data[['Subflow.Bwd.Bytes']])
data['scale_Init_Win_bytes_forward']=min_max_scaler.fit_transform(data[['Init_Win_bytes_forward']])
data['scale_Init_Win_bytes_backward']=min_max_scaler.fit_transform(data[['Init_Win_bytes_backward']])
data['scale_act_data_pkt_fwd']=min_max_scaler.fit_transform(data[['act_data_pkt_fwd']])
data['scale_min_seg_size_forward']=min_max_scaler.fit_transform(data[['min_seg_size_forward']])
data['scale_Active.Mean']=min_max_scaler.fit_transform(data[['Active.Mean']])
data['scale_Active.Std']=min_max_scaler.fit_transform(data[['Active.Std']])
data['scale_Idle.Mean']=min_max_scaler.fit_transform(data[['Idle.Mean']])
data['scale_Idle.Std']=min_max_scaler.fit_transform(data[['Idle.Std']])


data.drop(columns=['Flow.Duration','Total.Fwd.Packets','Total.Backward.Packets',
          'Total.Length.of.Fwd.Packets','Total.Length.of.Bwd.Packets','Fwd.Packet.Length.Mean','Fwd.Packet.Length.Std'
          ,'Bwd.Packet.Length.Mean','Bwd.Packet.Length.Std','Flow.Bytes.s','Flow.Packets.s','Flow.IAT.Mean','Flow.IAT.Std'
          ,'Fwd.IAT.Total','Fwd.IAT.Mean','Fwd.IAT.Std','Bwd.IAT.Total','Bwd.IAT.Mean','Bwd.IAT.Std','Fwd.Header.Length'
          ,'Bwd.Header.Length','Fwd.Packets.s','Bwd.Packets.s','Packet.Length.Variance','SYN.Flag.Count','PSH.Flag.Count',
          'ACK.Flag.Count','URG.Flag.Count','Down.Up.Ratio','Average.Packet.Size','Avg.Fwd.Segment.Size','Avg.Bwd.Segment.Size'
          ,'Fwd.Avg.Packets.Bulk','Subflow.Fwd.Packets','Subflow.Fwd.Bytes','Subflow.Bwd.Packets','Subflow.Bwd.Bytes',
          'Init_Win_bytes_forward','Init_Win_bytes_backward','act_data_pkt_fwd','min_seg_size_forward','Active.Mean',
          'Active.Std','Idle.Mean','Idle.Std'],inplace=True)

#print(data.head())

map_ProtocolName={'HTTP_PROXY':0, 'HTTP':1, 'HTTP_CONNECT':2, 'SSL':3, 'GOOGLE':4, 'YOUTUBE':5,
      'FACEBOOK':6, 'CONTENT_FLASH':7, 'DROPBOX':8, 'WINDOWS_UPDATE':9, 'AMAZON':10,
       'MICROSOFT':11, 'TOR':12, 'GMAIL':13, 'YAHOO':14, 'MSN':15, 'SSL_NO_CERT':16,
      'SKYPE':17, 'MS_ONE_DRIVE':18, 'MSSQL':19, 'TWITTER':20, 'APPLE_ICLOUD':21,
      'CLOUDFLARE':22, 'UBUNTUONE':23, 'OFFICE_365':24, 'WIKIPEDIA':25, 'OPENSIGNAL':26,
     'DNS':27, 'HTTP_DOWNLOAD':28, 'WHATSAPP':29, 'APPLE_ITUNES':30, 'FTP_DATA':31,
      'CITRIX':32, 'APPLE':33, 'MQTT':34, 'INSTAGRAM':35, 'EBAY':36, 'GOOGLE_MAPS':37,
      'IP_ICMP':38, 'NTP':39, 'TEAMVIEWER':40, 'SPOTIFY':41, 'EASYTAXI':42,
       'MAIL_IMAPS':43, 'TWITCH':44, 'NETFLIX':45, 'SSH':46, 'SIMET':47,
      'UNENCRYPED_JABBER':48, 'WAZE':49, 'UPNP':50, 'EDONKEY':51, 'OSCAR':52, 'ORACLE':53,
       'DEEZER':54, 'OPENVPN':55, 'WHOIS_DAS':56, 'SKINNY':57, 'STARCRAFT':58, 'NFS':59,
       'RTMP':60, 'TEAMSPEAK':61, 'SNMP':62, '99TAXI':63, 'QQ':64, 'TELEGRAM':65,
      'FTP_CONTROL':66, 'LOTUS_NOTES':67, 'H323':68, 'CITRIX_ONLINE':69, 'LASTFM':70,
       'IP_OSPF':71, 'CNN':72, 'BGP':73, 'RADIUS':74, 'SOCKS':75, 'BITTORRENT':76, 'TIMMEU':77}

 	
#data.fillna(data.mean(), inplace=True)

filename = 'model.sav'
#load the model from disk
loaded_model = pickle.load(open(filename, 'rb'))
results = loaded_model.predict(data)
#data['ProtocolName']=data['ProtocolName'].map(list)
app=[]
#for displaying keys from the values
for result in results:
    for key,value in map_ProtocolName.items(): 
        if result == value:
            app.insert(0,key)
data['ApplicationName']=app
print(data.head())
export_csv=data.to_csv(r'Flows_with_app_classified.csv',header=True)
