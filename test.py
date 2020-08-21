import pandas as pd


path = 'scenarios/TV200_DsmKroot1/log/20200115_135442/'

nav_msg_header = ['Date', 'Time', 'GNSS', 'SVID', 'WN', 'TOW', 'NavMessage']
nav_msg = pd.read_csv(path+'NavMsg.csv', header=None, names=nav_msg_header, index_col='Date')

pd.set_option('display.max_colwidth', None)
print(nav_msg[0:2])

gnss_is_galileo = nav_msg.GNSS == 0
svid_is_one = nav_msg.SVID == 1
all_filters = gnss_is_galileo & svid_is_one

nav_msg = nav_msg[all_filters]

nav_msg.to_csv(path+'NavMsg_01.csv')

new_nav_msg = pd.read_csv(path+'NavMsg_01.csv')

pd.set_option('display.max_colwidth', None)
print(nav_msg[0:2])


