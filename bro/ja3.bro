# This Bro script appends JA3 to ssl.log
# Version 1.3 (June 2017)
#
# Authors: John B. Althouse (jalthouse@salesforce.com) & Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

@load ./ja3_db

module JA3;

export {
    redef enum Log::ID += { LOG };

    type JA3FPStorage: record {
        client_version:  count &default=0 &log;
        client_ciphers:  string &default="" &log;
        extensions:      string &default="" &log;
        e_curves:        string &default="" &log;
        ec_point_fmt:    string &default="" &log;
    };



}

global ja3fp: table[string] of JA3FPStorage &create_expire=10min &redef;

redef record connection += {
       ja3fp: JA3FPStorage &synchronized &optional;
};

redef record SSL::Info += {
  ja3:            string &optional &log;
  ja3_client:     string &optional &log;
# LOG FIELD VALUES ##
#  ja3_version:  string &optional &log;
#  ja3_ciphers:  string &optional &log;
#  ja3_extensions: string &optional &log;
#  ja3_ec:         string &optional &log;
#  ja3_ec_fmt:     string &optional &log;
};

# Google. https://tools.ietf.org/html/draft-davidben-tls-grease-01
const grease: set[int] = {
    2570,
    6682,
    10794,
    14906,
    19018,
    23130,
    27242,
    31354,
    35466,
    39578,
    43690,
    47802,
    51914,
    56026,
    60138,
    64250
};
const sep = "-";
event bro_init() {
    Log::create_stream(JA3::LOG,[$columns=JA3FPStorage, $path="ja3fp"]);
}



event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
{
    if ( c$uid !in ja3fp)
        ja3fp[c$uid]=JA3FPStorage();
    if ( is_orig = T ) {
        if ( code in grease ) {
            next;
        }
        if ( ja3fp[c$uid]$extensions == "" ) {
            ja3fp[c$uid]$extensions = cat(code);
        }
        else {
            ja3fp[c$uid]$extensions = string_cat(ja3fp[c$uid]$extensions, sep,cat(code));
        }
    }
}

event ssl_extension_ec_point_formats(c: connection, is_orig: bool, point_formats: index_vec)
{
    if ( c$uid !in ja3fp)
        ja3fp[c$uid]=JA3FPStorage();
    if ( is_orig = T ) {
        for ( i in point_formats ) {
            if ( point_formats[i] in grease ) {
            next;
            }
            if ( ja3fp[c$uid]$ec_point_fmt == "" ) {
                ja3fp[c$uid]$ec_point_fmt += cat(point_formats[i]);
            }
            else {
                ja3fp[c$uid]$ec_point_fmt += string_cat(sep,cat(point_formats[i]));
            }
        }
    }
}

event ssl_extension_elliptic_curves(c: connection, is_orig: bool, curves: index_vec)
{
    if ( c$uid !in ja3fp)
        ja3fp[c$uid]=JA3FPStorage();
    if ( is_orig = T  ) {
        for ( i in curves ) {
            if ( curves[i] in grease ) {
            next;
            }
            if ( ja3fp[c$uid]$e_curves == "" ) {
                ja3fp[c$uid]$e_curves += cat(curves[i]);
            }
            else {
                ja3fp[c$uid]$e_curves  += string_cat(sep,cat(curves[i]));
            }
        }
    }
}

event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec) &priority=1
{
    if ( c$uid !in ja3fp)
        ja3fp[c$uid]=JA3FPStorage();
    ja3fp[c$uid]$client_version = version;
    for ( i in ciphers ) {
        if ( ciphers[i] in grease ) {
            next;
        }
        if ( ja3fp[c$uid]$client_ciphers == "" ) {
            ja3fp[c$uid]$client_ciphers += cat(ciphers[i]);
        }
        else {
            ja3fp[c$uid]$client_ciphers += string_cat(sep,cat(ciphers[i]));
        }
    }
    local sep2 = ",";
    local ja3_string = string_cat(cat(ja3fp[c$uid]$client_version),sep2,ja3fp[c$uid]$client_ciphers,sep2,ja3fp[c$uid]$extensions,sep2,ja3fp[c$uid]$e_curves,sep2,ja3fp[c$uid]$ec_point_fmt);
    local ja3fp_1 = md5_hash(ja3_string);
    c$ssl$ja3 = ja3fp_1;
    if ( ja3fp_1 in JA3Fingerprinting::database ) {
        c$ssl$ja3_client = JA3Fingerprinting::database[ja3fp_1];
    }



# LOG FIELD VALUES ##
#c$ssl$ja3_version = cat(c$ja3fp$client_version);
#c$ssl$ja3_ciphers = c$ja3fp$client_ciphers;
#c$ssl$ja3_extensions = c$ja3fp$extensions;
#c$ssl$ja3_ec = c$ja3fp$e_curves;
#c$ssl$ja3_ec_fmt = c$ja3fp$ec_point_fmt;
#
# FOR DEBUGGING ##
#print "JA3: "+ja3fp_1+" Fingerprint String: "+ja3_string;

}
