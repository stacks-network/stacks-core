LOG_FILE=$1
OUTPUT_FILE=$2
cat ${LOG_FILE} | python extract_data.py ${OUTPUT_FILE}
