import config
from config import log_file_path

LOGGING_CONFIG = { 
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': { 
        'standard': { 
            'format': '%(asctime)s - %(levelname)-8s %(message)s', 'datefmt': '%a, %d %b %Y %H:%M:%S' 
        },
    },
    'handlers': { 
        'TimedFileRotator': { 
            'level': 'DEBUG',
            'formatter': 'standard',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': log_file_path,
            'when': 'd',
            'interval': 1,
            'backupCount': 4
        },
        'Syslogger': { 
            'level': 'CRITICAL',
            'formatter': 'standard',
            'class': 'logging.handlers.SysLogHandler',
            'address': ('ip_addr', 514),
        },
    },
    'loggers': { 
        'timedLogger': { 
            'handlers': ['TimedFileRotator'],
            'level': 'DEBUG',
            'propagate': False
        },
        'SysLogger': {
            'handlers': ['Syslogger'],
            'level': 'CRITICAL',
            'propagate': False
        }
    } 
}    
