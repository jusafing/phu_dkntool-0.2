#!/usr/bin/perl
############################################################################
############################################################################
# DKN ProcessTool v0.1b
# National Autonomous University of Mexico
# UNAM-CERT / Honeynet Project - UNAM Chapter / Proyecto Honeynet UNAM
# By Javier Santillan <jusafing@gmail.com> 2009-2010
# www.seguridad.unam.mx/www.cert.org.mx/www.honeynet.unam.mx/www.jusanet.org
# 
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# 
# dkn_htconn.pl
# DKN ProcessTool - Module for honeytrap information. 
############################################################################
############################################################################
use strict;
package VARS_GLOB;
	our $flag_found_rule   		= 0;
	our $flag_found_event  		= 0;
	our $flag_found_ps     		= 0;
	our $event_count       		= 0;
	our $nopsw             		= 0;
	our $verify_event_exec 		= 0;
	our $pswpend           		= 0;
	our $active_events_file		= "$CONFIG_VARS::ht_tmpdir/active_events.tmp";
	our $active_portsweep_file	= "$CONFIG_VARS::ht_tmpdir/active_portsweep.tmp";
use DKNCONF;
######################################################################
##############################################################################################################################################################################################
sub get_event_info()
{
	logmsg("[CONNECTION | INFO          ] PROCESSING ($ARGV[0])\n");
	package EVENT_INFO;
	our @cevent_data           = split(/\|/,$ARGV[0]);
	our $current_event_ts      = $cevent_data[0];
	our $current_event_proto   = lc($cevent_data[1]);
	our $current_event_sip     = $cevent_data[2];
 	our $current_event_sport   = $cevent_data[3];
	our $current_event_dip     = $cevent_data[4];
	our $current_event_dport   = $cevent_data[5];
	our $current_event_logtime = $current_event_ts;
	our $current_event_aeid    = "$current_event_proto-$current_event_sip-$current_event_dport";
	our $current_event_psid    = "$current_event_proto-$current_event_sip-$current_event_sport-$current_event_dip";
	our $event_data	           = "$current_event_ts $current_event_proto-$current_event_sip-$current_event_sport-$current_event_dip-$current_event_dport";
	our $current_event_type;
	our $current_event_rule_pattern;
	our $current_event_timerule;
}
##############################################################################################################################################################################################
sub search_rule()
{
	my @rule_line;
	$VARS_GLOB::flag_found_rule=0;
	logmsg("[CONNECTION | search_rule   ]   Reading rules file ($CONFIG_VARS::rules_file)\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
	open(RULES_FD,"<$CONFIG_VARS::rules_file") || logmsg("[CONNECTION | search_rule]   ERROR, Unable to open rules file ($CONFIG_VARS::rules_file)\n");
	while(<RULES_FD>)
	{
		chomp();
		next if ( $_ =~ /^#/ );
		next unless ( $_ =~ /.*\|.*\|.*\|.*\|.*/ );
		@rule_line=split(/\|/,$_);
		if ( $rule_line[2] == $EVENT_INFO::current_event_dport )
		{
			$VARS_GLOB::current_event_type=$rule_line[0];
		        $VARS_GLOB::flag_found_rule=1;
			$VARS_GLOB::current_event_timerule=$rule_line[4];
			$VARS_GLOB::current_event_rule_pattern=$rule_line[3];
			last;
		}
	}
	if ($VARS_GLOB::flag_found_rule == 0){
		$VARS_GLOB::current_event_type="GENERAL SCAN PORT [$EVENT_INFO::current_event_dport]";
		$VARS_GLOB::current_event_timerule=$CONFIG_VARS::ht_default_time_rule;
	}
	close(RULES_FD);
}
##############################################################################################################################################################################################
sub verify_event()
{
	open(ACTIVE_EVENTS_FD,"<$VARS_GLOB::active_events_file.it") || logmsg("[CONNECTION | verify_event  ]   ERROR, Unable to open active events file ($VARS_GLOB::active_events_file.it)\n");
	while(<ACTIVE_EVENTS_FD>)
	{
		chomp();
		my @aevent_line=split(/\|/,$_);
		if ( ($aevent_line[1] eq $EVENT_INFO::current_event_aeid) || ($aevent_line[1] eq $EVENT_INFO::current_event_psid) )
		{
			$VARS_GLOB::flag_found_event=1 if (($aevent_line[1] eq $EVENT_INFO::current_event_aeid));
			$VARS_GLOB::flag_found_event=2 if (($aevent_line[1] eq $EVENT_INFO::current_event_psid));
			$VARS_GLOB::event_count=$aevent_line[0];
			$VARS_GLOB::event_count++;
			$EVENT_INFO::current_event_logtime=$aevent_line[3];
			last
		}
	}
	close(ACTIVE_EVENTS_FD);
	if ($VARS_GLOB::flag_found_event == 0)
	{
		open(ACTIVE_EVENTS_FD,"<$VARS_GLOB::active_events_file") || logmsg("[CONNECTION | verify_event  ]   ERROR, Unable to open active events file ($VARS_GLOB::active_events_file.it)\n");
		while(<ACTIVE_EVENTS_FD>)
		{
			chomp();
			my @aevent_line=split(/\|/,$_);
			if ( ($aevent_line[1] eq $EVENT_INFO::current_event_aeid) || ($aevent_line[1] eq $EVENT_INFO::current_event_psid) )
			{
				$VARS_GLOB::flag_found_event=1 if (($aevent_line[1] eq $EVENT_INFO::current_event_aeid));
				$VARS_GLOB::flag_found_event=2 if (($aevent_line[1] eq $EVENT_INFO::current_event_psid));
				$VARS_GLOB::event_count=$aevent_line[0];
				$VARS_GLOB::event_count++;
				$EVENT_INFO::current_event_logtime=$aevent_line[3];
				last
			}
		}
		close(ACTIVE_EVENTS_FD);
	}
	open(ACTIVE_EVENTS_FD,">>$VARS_GLOB::active_events_file") || logmsg("[CONNECTION |verify_event   ]   ERROR, Unable to open active events file ($VARS_GLOB::active_events_file)\n");
	if($VARS_GLOB::flag_found_event == 1)
	{
		logmsg("[CONNECTION | verify_event  ]   EVT active [$EVENT_INFO::current_event_aeid]-> Increasing counter\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
		$VARS_GLOB::nopsw=1;
	}
	elsif($VARS_GLOB::flag_found_event == 2)
	{
		logmsg("[CONNECTION | verify_event  ]   EVT active [$EVENT_INFO::current_event_psid]-> Increasing counter\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
		$EVENT_INFO::current_event_aeid=$EVENT_INFO::current_event_psid;
		$VARS_GLOB::nopsw=1;
	}
	else
	{
		if($VARS_GLOB::pswpend == 1)
		{
			$EVENT_INFO::current_event_aeid = "$EVENT_INFO::current_event_proto-$EVENT_INFO::current_event_sip-$EVENT_INFO::current_event_sport-$EVENT_INFO::current_event_dip";
			$VARS_GLOB::current_event_type="PORTSWEEP";
			$VARS_GLOB::flag_found_ps = 1;
		}
		print ACTIVE_EVENTS_FD "X|$EVENT_INFO::current_event_aeid|$EVENT_INFO::current_event_limittime|$EVENT_INFO::current_event_logtime|$VARS_GLOB::current_event_type|$VARS_GLOB::current_event_rule_pattern\n";
		logmsg("[CONNECTION | verify_event  ]   Adding EVT $EVENT_INFO::current_event_aeid\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
	}
	close(ACTIVE_EVENTS_FD);
	$VARS_GLOB::verify_event_exec=1;
}
##############################################################################################################################################################################################
sub verify_portsweep()
{
	open(ACTIVE_PS_FD,"<$VARS_GLOB::active_portsweep_file") || logmsg("[CONNECTION | verify_portswp]   ERROR, Unable to open PSW file ($VARS_GLOB::active_portsweep_file)\n");
	while(<ACTIVE_PS_FD>)
	{
		chomp();
		my @psw_line=split(/\|/,$_);
		if ( $psw_line[0] eq $EVENT_INFO::current_event_psid )
		{
			$EVENT_INFO::current_event_limittime=$psw_line[1];
			$VARS_GLOB::pswpend = 1;
			logmsg("[CONNECTION | verify_portswp]   Match found PSW ($EVENT_INFO::current_event_psid) - ($psw_line[0])\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
			verify_event();
			last;
		}
	}
	close(ACTIVE_PS_FD);
	if ($VARS_GLOB::verify_event_exec == 0)
	{
###############################
		open(ACTIVE_PS_FD,">>$VARS_GLOB::active_portsweep_file") || print "ERROR, Unable to write file ($VARS_GLOB::active_portsweep_file)\n";
		if($VARS_GLOB::flag_found_ps == 1)
		{
			logmsg("[CONNECTION | verify_portswp]   PSW active\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
		}
		else
		{
			$EVENT_INFO::current_event_limittime    = $EVENT_INFO::current_event_ts + $VARS_GLOB::current_event_timerule;
			chomp($EVENT_INFO::current_event_limittime);
			print ACTIVE_PS_FD "$EVENT_INFO::current_event_proto-$EVENT_INFO::current_event_sip-$EVENT_INFO::current_event_sport-$EVENT_INFO::current_event_dip|$EVENT_INFO::current_event_limittime\n";
			logmsg("[CONNECTION | verify_portswp]   Adding PSW $EVENT_INFO::current_event_psid\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
		}
		close(ACTIVE_PS_FD);
		verify_event();
	}
}
##############################################################################################################################################################################################
sub add_connection()
{
	open(EVENT_CONN_FD,"+>>$CONFIG_VARS::ht_dir/events_connections/$EVENT_INFO::current_event_aeid-$EVENT_INFO::current_event_logtime.evt") || die "ERROR, Unable to write file ($CONFIG_VARS::ht_dir/events_connections/$EVENT_INFO::current_event_aeid-$EVENT_INFO::current_event_logtime.evt)\n";
	logmsg("[CONNECTION | add_conn      ]   Adding INFO to ($CONFIG_VARS::ht_dir/events_connections/$EVENT_INFO::current_event_aeid-$EVENT_INFO::current_event_logtime.evt)\n");
	print EVENT_CONN_FD "$EVENT_INFO::event_data\n";
	close(EVENT_CONN_FD);
}
##############################################################################################################################################################################################
sub logmsg()
{
	my $msg= shift;
	(my $sec,my $min,my $hour,my $mday,my $mon,my $year,my $wday,my $yday,my $isdst)=localtime(time);
	printf LOGFILE_FD "[%4d-%02d-%02d %02d:%02d:%02d] - %s",$year+1900,$mon+1,$mday,$hour,$min,$sec,$msg;
}
##############################################################################################################################################################################################
open(LOGFILE_FD,">>$CONFIG_VARS::ht_logfile_conn");
	get_event_info();
	unless ( ($EVENT_INFO::current_event_sip eq "132.248.10.2" || $EVENT_INFO::current_event_sip eq "132.248.204.1" ) && $EVENT_INFO::current_event_sport  == 53)
	{
		search_rule();
		verify_portsweep();
		add_connection();
	}
close(LOGFILE_FD);
##############################################################################################################################################################################################
##############################################################################################################################################################################################
