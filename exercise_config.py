class Config:
    '''
    Configurations determine the behavior of the exercise program
    '''
    timeout = 1 #Frequency in sec to check for new HTTP transaction, default 2s
    dashboard_bucket_size = 10 #Frequency in sec to refresh dashboard info, default 10s
    average_bucket_size = 60*2 #Bucket size in sec for average HTTP request rate, default 2mins
    average_threshold = 10 #Threshold in percentage to trigger alerts when exceeding <average_baseline>, default 10%
    average_learning_duration = average_bucket_size #Duration of learning for average HTTP request rate, default 2mins
    max_str_length = 1024 #Protection of overlong string, default set to 1kb
    max_top_hits = 10 #Display top N hits on screen, hide the rest, default 10 hits
    max_retention_length = 3600*24 #Retention length in sec, used to purge aging data, default 24hrs
