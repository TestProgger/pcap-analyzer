import subprocess
import json
import datetime
def pcap2json( pcap_path : str ):
    try:
        result = subprocess.run(["tshark", "-r", pcap_path, "-T", "json"], stdout=subprocess.PIPE, text=True)
        return json.loads(result.stdout)
    except Exception as ex:
        return ''

def string_frame_time_to_timestamp( frame_time : str ) -> float :
    month_dict = {
        "Jan" : 1,
        "Feb" : 2,
        "Mar" : 3,
        "Apr" : 4,
        "May" : 5,
        "Jun" : 6,
        "Jul" : 7,
        "Aug" : 8,
        "Sept" : 9,
        "Oct" : 10,
        "Nov" : 11,
        "Dec" : 12
    }
    month , day , year , time , tz = frame_time.split(" ")
    hour , minutes , seconds_with_micro = time.split(":")
    seconds , microseconds = seconds_with_micro.split('.')

    return  datetime.datetime(
        int(year),
        month_dict[month],
        int(day.replace("," , "")),
        int(hour),
        int(minutes),
        int(seconds),
        int(microseconds[0:6]),
    ).timestamp()


