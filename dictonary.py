import csv


def read_csv():
    dictionaries = {}
    file_names = [
        'phones.csv',
        'dev_sig.csv',
        'airpods_states.csv',
        'proximity_dev_models.csv',
        'proximity_colors.csv',
        'homekit_category.csv',
        'siri_dev.csv',
        'magic_sw_wrist.csv',
        'hotspot_net.csv',
        'ble_packets_types.csv',
        'devices_models.csv',
        'airpods_states.csv',
        'phone_states.csv'
    ]
    for file_name in file_names:
        dictionary = {}
        try:
            with open(file_name, 'r', newline='') as csvfile:
                reader = csv.reader(csvfile)
                for row in reader:
                    dictionary[row[0]] = row[1]
        except FileNotFoundError:
            pass
        dictionaries[file_name] = dictionary
    return dictionaries


dictionaries = read_csv()
iphones = dictionaries['phones.csv']
dev_sig = dictionaries['dev_sig.csv']
proximity_dev_models = dictionaries['proximity_dev_models.csv']
proximity_colors = dictionaries['proximity_colors.csv']
homekit_category = dictionaries['homekit_category.csv']
siri_dev = dictionaries['siri_dev.csv']
magic_sw_wrist = dictionaries['magic_sw_wrist.csv']
hotspot_net = dictionaries['hotspot_net.csv']
ble_packets_types = dictionaries['ble_packets_types.csv']
devices_models = dictionaries['devices_models.csv']
airpods_states = dictionaries['airpods_states.csv']
phone_states = dictionaries['phone_states.csv']
