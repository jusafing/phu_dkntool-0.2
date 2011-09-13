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
# dkn_htmod_a.pl
# DKN ProcessTool - Agent for process information of Honeytrap module.
############################################################################
############################################################################
use strict;
package AGENT_VARS_GLOB;
use Digest::MD5;
use Linux::Pid;
use POSIX ":sys_wait_h";
use DBI;
use DateTime;
use Net::SCP::Expect;
use Archive::Tar;
use File::Touch;
use File::Copy;
use Socket;
use InsertDB;
use DKNCONF;
our $countexec=0;
our $dbconn;
our $stamintime=300;
our $active_portsweep_file	= "$CONFIG_VARS::ht_tmpdir/active_portsweep.tmp";
our $active_events_file		= "$CONFIG_VARS::ht_tmpdir/active_events.tmp";
##############################################################################################################################
##############################################################################################################################
open(LOGFILE_FD,"+>>$CONFIG_VARS::ht_logfile_agent") || die "ERROR, Unable to open log file ($CONFIG_VARS::ht_logfile_agent)\n";
check_proc();
check_active_events();
close(LOGFILE_FD);
##############################################################################################################################
##############################################################################################################################
sub check_proc()
{
	logmsg("********************* [ACTIVE EVENTS AGENT] *********************\n");
	logmsg("*****************************************************************\n\n");
	chomp(my @procs_agent =`ps -aef | grep 'perl.*dkn_agent.pl' | grep -v grep`);
	my $procs=@procs_agent;
	die "[AGENT($AGENT_VARS_GLOB::countexec)]   ERROR, There is another dkn_agent.pl process already running\n[@procs_agent]\n" if ( $procs > 1 );
}
##############################################################################################################################
sub check_active_events()
{
	if ($CONFIG_VARS::scp_enable == 1)
	{
		my $pid_inc_trasfer_mode;
        	logmsg("[AGENT | check_active_events   ] STARTING SCP TRANSFER MODE (NO DB) ($CONFIG_VARS::scp_ttime)sec\n");
		$SIG{CHLD} = 'IGNORE';
	       	$pid_inc_trasfer_mode = fork();
	       	if( $pid_inc_trasfer_mode == 0 )
        	{
			scp_transfer($CONFIG_VARS::scp_ttime);
                	exit 1;
        	}
	        elsif(not defined $pid_inc_trasfer_mode)
        	{
        		logmsg("[AGENT | check_active_events] ERROR, Unable to create process of TRANSFER MODE\n");
	        }
	}
	while( 1 == 1)
	{
		logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | check_active_events] STARTING VERIFICATION PROCESS\n");
		my $aev_file_it		= "$AGENT_VARS_GLOB::active_events_file.it";
		my $psw_file_it		= "$AGENT_VARS_GLOB::active_portsweep_file.it";
		my $aev_file_proc	= "$AGENT_VARS_GLOB::active_events_file.proc";
		my $psw_file_proc	= "$AGENT_VARS_GLOB::active_portsweep_file.proc";
		touch($aev_file_it);	
		touch($psw_file_it);
##		logmsg(">>>>>> Copiando [$AGENT_VARS_GLOB::active_events_file] [$aev_file_proc] <<<<<<<<<\n");
		rename($AGENT_VARS_GLOB::active_events_file,$aev_file_proc)    || logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | check_active_events] ERROR, Unable to copy evt file ($aev_file_proc)\n");
		touch($AGENT_VARS_GLOB::active_events_file);	
		`cat $aev_file_it >> $aev_file_proc`; 
		unlink("$aev_file_it");
		expire_event_file($aev_file_proc,$aev_file_it,1);
		rename($AGENT_VARS_GLOB::active_portsweep_file,$psw_file_proc) || logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | check_active_events] ERROR, Unable to copy psw file [$psw_file_proc]\n");
		touch($AGENT_VARS_GLOB::active_portsweep_file);	
		`cat $psw_file_it >> $psw_file_proc`; 
		unlink("$psw_file_it");
		expire_event_file($psw_file_proc,$psw_file_it,0);
		sleep($CONFIG_VARS::ht_time_refresh_agent);
		$AGENT_VARS_GLOB::countexec++;
	}
}
##############################################################################################################################
sub expire_event_file()
{
	my $exp_file     = shift;
	my $noexp_file   = shift;
	my $type_file    = shift;
	my $evtexp_file  = "$CONFIG_VARS::ht_tmpdir/AGENT$AGENT_VARS_GLOB::countexec.exp" if ($type_file == 1);
	my $current_date = time();
#	logmsg("-----EXP_FILE [$exp_file]-- NOEXP [$noexp_file]-- TYPE_FILE [$type_file] -----\n");
	open(exp_file_FD,"<$exp_file")|| logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | check_active_events ]  ERROR, Unable to open file ($exp_file)\n");
	open(new_exp_file_FD,">>$noexp_file")|| logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | check_active_events ]  ERROR, Unable to write file ($noexp_file)\n");
	open(current_evt_to_expire_FD,">>$evtexp_file") || logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | check_active_events ]  ERROR, Unable to write on file ($evtexp_file)\n") if ($type_file == 1);
	while(<exp_file_FD>)
	{
		chomp();
		my @aefile_line=split(/\|/,$_);
##		logmsg("###### LINE EXP_FILE [$_] ######\n");
		if($type_file == 1)
		{
##			logmsg("###### RESTANDO $aefile_line[2] - $current_date #####\n");
			my $res=$aefile_line[2] - $current_date;
			logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | expire_event_file  ]   Event AEV [$aefile_line[1]]: <$res>\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
			if ( $res <= 0 )
			{
#				logmsg("####### INFO [$aefile_line[1]] ########\n");
				my @flowdata=split(/\-/,$aefile_line[1]);
				my $evt_file="$CONFIG_VARS::ht_dir/events_connections/$aefile_line[1]-$aefile_line[3].evt";
				logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | expire_event_file  ]   Expiring event AEV: [$_] \n");
				logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | expire_event_file  ]   Adding incident to agent file : [$evtexp_file] \n");
				print current_evt_to_expire_FD "$flowdata[0]|$flowdata[1]|$aefile_line[2]|$aefile_line[3]|$aefile_line[4]|$evt_file|$aefile_line[5]\n";	
			}
			else
			{
#				logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | expire_event_file  ]     Devolviendo incidente [$_] AEV\n");
				print new_exp_file_FD "$_\n";
			}
		}
		else
		{
			my $res=$aefile_line[1] - $current_date;
			logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | expire_event_file  ]   Event PSW [$aefile_line[0]] : <$res>\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
			if ( $res <= 0 )
			{
				logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | expire_event_file  ]   Expiring event PSW: [$aefile_line[1]] \n") if ($CONFIG_VARS::DEBUG_MODE == 1);
			}
			else
			{
				print new_exp_file_FD "$_\n";
			}
		}
	}
	close(exp_file_FD);
	close(current_evt_to_expire_FD);
	if ($type_file == 1)
	{
		logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | expire_event_file  ]   Event file has been readed > Created ($evtexp_file)\n");
		start_proc($evtexp_file);
	}
	else
	{
		logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | expire_event_file  ]   Event file PSW has been readed \n");
	}
	``;		## Esta linea es muy importante, no sirve para nada y a la vez sirve para todo. Ayudame tio gamboin.
}
##############################################################################################################################
sub start_proc()
{
	my $exp_evt_file=shift;
	logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | start_proc         ]   Verifying incidents of file [$exp_evt_file]\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
	open(exp_evt_file_FD,"<$exp_evt_file") || logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | start_proc         ]  ERROR, Unable to open file ($exp_evt_file)\n");
	while(<exp_evt_file_FD>)
	{
		logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | start_proc         ]   Creating new process for event ($exp_evt_file)\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
		chomp();
		my $pid_exp_evt_file;
		$SIG{CHLD} = 'IGNORE';
		$pid_exp_evt_file = fork();
		if( $pid_exp_evt_file == 0 )
		{
			my $pidnumber=Linux::Pid::getpid();
			logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | start_proc         ]   PID $pidnumber > [$exp_evt_file]\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
			proc_events($_);
			exit 1;
		}
		elsif(not defined $pid_exp_evt_file)
		{
			logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | start_proc         ] ERROR, Unable to create new process for event [$exp_evt_file]\n");
		}
	}
	close(inter_evt_file_FD);
	logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | start_proc         ]   Deleting event file [$exp_evt_file]\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
	unlink("$exp_evt_file");
}
##############################################################################################################################
sub proc_events()
{
	my $incident_line =  shift;
	my @incident_info =  split(/\|/,$incident_line);
	my $pattern_rule  =  $incident_info[6];
	my $evt_file	  =  $incident_info[5];
	my $det_file	  =  $incident_info[5];
	$det_file	  =~ s/\.evt/\.det/g;
	my $evt_count	  =  0;
	my $tgz_file      =  "";
	my %payloads;
	my @files_payload;
	open(INCIDENT_FD,"<$evt_file") || logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | proc_events        ]   ERROR, Unable to open file ($evt_file)\n");
	open(INCIDENT_DET_FD,"+>>$det_file") || logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | proc_events        ]   ERROR, Unable to open file ($det_file)\n");
	logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | proc_events        ]   Analyzing EVT file [$evt_file]\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
	while(<INCIDENT_FD>)
	{
		chomp();
		my @filesinc    = split(" ",$_);
		my @event_info  = split("-",$filesinc[1]);
		my $pfsip	= iptodecv($event_info[1]); 
		my $pfdip	= iptodecv($event_info[3]); 
		my $payloadfile = "$CONFIG_VARS::ht_payloads_dir/$event_info[0]-$pfsip-$event_info[2]-$pfdip-$event_info[4]";
		my $md5;
		my $newnamepayload;
		my $strevt;
		logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | proc_events        ]     >> Analyzing event: ($payloadfile)\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
		if ( -e $payloadfile )
		{
			$md5 = md5sum_mod($payloadfile);
			$strevt=search_strings($payloadfile,"$pattern_rule");
			$newnamepayload = "$CONFIG_VARS::ht_payloads_dir/$md5";
			logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | proc_events        ]        Adding info to ($det_file)\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
			print INCIDENT_DET_FD "$filesinc[0]|$event_info[1]|$event_info[2]|$event_info[3]|$event_info[4]|$md5|$strevt|\n";
			logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | proc_events        ]        * Changing payload name ($payloadfile) -> ($newnamepayload)\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
			rename("$payloadfile","$newnamepayload");
			$payloads{$newnamepayload}=0;
		}
		else
		{
			$strevt="||||";
			logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | proc_events        ]        Adding info to ($det_file)\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
			print INCIDENT_DET_FD "$filesinc[0]|$event_info[1]|$event_info[2]|$event_info[3]|$event_info[4]||$strevt|\n";
			logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | proc_events        ]        * No payload found ($det_file)\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
		}
		$evt_count++;
	}
	close(INCIDENT_FD);
	close(INCIDENT_DET_FD);
	@files_payload= (keys%payloads);
	if (@files_payload > 0)
	{
		$tgz_file = $incident_info[5];
		$tgz_file =~ s/\.evt/\.tgz/g;
		my $files = "@files_payload";
		createtar($tgz_file,$files);
	}
	logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | proc_events        ]     Deleting EVT file ($evt_file) \n") if ($CONFIG_VARS::DEBUG_MODE == 1);
	unlink("$evt_file");
	logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | proc_events        ]     Logging new Incident from [$evt_file] \n");
#	logmsg("XXXXXXXXXX [$incident_info[2]] [$incident_info[3]] XXXXXXXXXXXx\n");
        my $dtl = DateTime->from_epoch( epoch => $incident_info[2] );
        my $dtf = DateTime->from_epoch( epoch => $incident_info[3] );
	open(INCFILE_FD,"+>>$CONFIG_VARS::ht_incident_file") || logmsg("ERROR, Unable to open incident file ($CONFIG_VARS::ht_incident_file)\n");
	print INCFILE_FD "dkn|$evt_count|$incident_info[0]|$incident_info[1]|||||||$dtl|$dtf|$incident_info[4]|$det_file|$tgz_file|\n" if ($evt_count > 0);	
	close(INCFILE_FD);
	if ($CONFIG_VARS::db_enable == 1)
	{
		logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | proc_events        ]     Storing new Incident into DB from ($evt_file)\n");
		InsertDB::insert("dkn1|$evt_count|$incident_info[0]|$incident_info[1]|||||||$dtl|$dtf|$incident_info[4]|$det_file|@files_payload|",$CONFIG_VARS::ht_logfile_agent,"DATA");
	}
}
##############################################################################################################################
sub createtar()
{
        my $outfile = shift;
        my $files   = shift;
        my @array   = split(" ",$files);
	logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | createtar          ]     Creating Tar file ($outfile) with (@array)\n"); 
        my $tar = Archive::Tar->new;
        $tar->add_files(@array);
        $tar->write($outfile, COMPRESS_GZIP);
}
##############################################################################################################################
sub md5sum_mod()
{
    my $file = shift;
    open(FILE, $file) || logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | md5sum_mod]   ERROR, Unable to open payload file ($file)\n");
    binmode(FILE);
    my $md5sum=Digest::MD5->new->addfile(*FILE)->hexdigest;
    return $md5sum;
}
##############################################################################################################################
sub search_strings()
{
	my $arch=shift;
	my $pattern_rule=shift;
	my $oct='[0-9]{1,3}';
	my $flag;
	my %dominios;
	my %ips;
	my %correos;
	my %urls;
	my $patron_inc=0;
	my $correostr;
	my $urlstr;
	my $ipstr;
	my $dominiostr;
	if    ($pattern_rule eq "-"){$flag=2;logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | search_strings     ]        * Event without pattern\n") if ($CONFIG_VARS::DEBUG_MODE == 1);}
	elsif ($pattern_rule =~ m/.+/g){$flag=1;logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | search_strings     ]        * Defined pattern ($pattern_rule)\n") if ($CONFIG_VARS::DEBUG_MODE == 1);}
	else  {$flag=0;logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | search_strings     ]        * Patron indefinido\n") if ($CONFIG_VARS::DEBUG_MODE == 1);}
	if ( -B $arch)
	{
		logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | search_strings     ]        * Binary Payload -> Creating temporal strings file ($arch.tmp)\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
		`strings $arch > $arch.tmp`;
		open(arch_FD,"<$arch.tmp") || logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | search_strings     ]       * ERROR, Unable to open strings file. [$arch]\n");
	}
	else
	{
		logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | search_strings     ]        * Text payload -> processing [$arch]\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
		if ( -e $arch ){
			open(arch_FD,"<$arch") || logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | search_strings     ]        * ERROR, File exists but unable to open strings file ($arch)\n");
		}
		else
		{
			logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | search_strings     ]        * WARNING, Unable to find strings file. Possible scan without payload ($arch)\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
		}
	}
	while (<arch_FD>)
	{
		chomp();
		if( $flag == 1 && $_ =~ m/.*$pattern_rule.*/g){
			$patron_inc++;
		}
		my @line=split(" ",$_);
		foreach my $palabra (@line)
	        {
			if ($palabra =~ /[^a-z]*([a-z]([a-z0-9]*[-._]?[a-z0-9]+)+\@(([a-z0-9]+\-?[a-z0-9]+\.)+[a-z0-9]+))/gi){
		       		$correos{$1}++; 
			}
			elsif ($palabra =~ /(((ftp|http|https|tftp|sftp|link)\:\/\/|www\.)(([a-z0-9]+\-?[a-z0-9]+\.)+[a-z0-9]+)((\/\~?[a-z0-9]+\-?[a-z0-9]+)+(\.[a-z0-9]+)?)*)/gi){
				$urls{$1}++;
				$dominios{$4}++;
			}
			elsif ( ($palabra =~ /(($oct)\.($oct)\.($oct)\.($oct))/g) && ($2<256) && ($3<256) && ($4<256) && ($5<256) ){
				$ips{$1}++;
			}
        	}
	}
	close(arch_FD);
	unlink("$arch.tmp");
	foreach my $correo (keys%correos)
	{
		$correostr .= "$correo($correos{$correo}),";
	}
	foreach my $url (keys%urls)
	{
		$urlstr .= "$url($urls{$url}),";
	}
	foreach my $dominio (keys%dominios)
	{
		$dominiostr .= "$dominio($dominios{$dominio}),";
	}
	foreach my $ip (keys%ips)
	{
		$ipstr .= "$ip($ips{$ip}),";
	}
	return "$correostr|$urlstr|$dominiostr|$ipstr|$pattern_rule($patron_inc)";
}
##############################################################################################################################
sub stamod()
{
	my $pidnumber=Linux::Pid::getpid();
       	logmsg("[AGENT | stamod                ] Executing STA Module PID Handler($pidnumber)\n");
	exec "/usr/bin/perl $CONFIG_VARS::confdir/dkn_stamod.pl $CONFIG_VARS::exectime";
}
##############################################################################################################################
sub scp_transfer()
{
	my $ttime=shift;
	my @files=($CONFIG_VARS::ht_incident_file,$CONFIG_VARS::sta_incident_file);
	while ( 1 == 1)
	{
		sleep($ttime);
		(my $sec,my $min,my $hour,my $mday,my $mon,my $year,my $wday,my $yday,my $isdst)=localtime(time);
		$year += 1900;
		$mon  += 1;
		foreach my $i (@files)
		{
			my $tmpincname="$i.$year$mon$mday\_$hour$min";
			rename($i,$tmpincname);
			touch($i);
			my $pid_transfer;
			$SIG{CHLD} = 'IGNORE';
		       	$pid_transfer = fork();
		       	if( $pid_transfer == 0 )
        		{
				my $pidnumber=Linux::Pid::getpid();
				transfer_file($tmpincname);
				open(INCFILE,"<$tmpincname") || logmsg("[AGENT    | scp_transfer       ]   ERROR, Unable to open file ($tmpincname)\n");
				while(<INCFILE>)
				{
					chomp();
					next unless ($_ =~ /.+/);
					my @campos = split(/\|/,$_);
					transfer_file($campos[13]);
					transfer_file($campos[14]);
				}
        	        	exit 1;
        		}
		        elsif(not defined $pid_transfer)
        		{
        			logmsg("[AGENT | scp_transfer        ]   ERROR, Unable to create process to TRANSFER INC FILE\n");
	        	}
		}
	}
}
##############################################################################################################################
sub transfer_file()
{
	my $file = shift;
	my $host = $CONFIG_VARS::scp_host;
	my $port = $CONFIG_VARS::scp_port;
	my $user = $CONFIG_VARS::scp_user;
	my $pass = $CONFIG_VARS::scp_pass;
	my $dstp = $CONFIG_VARS::scp_dstp;
	my $pidnumber=Linux::Pid::getpid();
	my $ppidnumber=Linux::Pid::getppid();
	return unless (-e $file);
	logmsg("[AGENT | transfer_file          ]     Transfering ($host:$port|$user|****|$dstp|$file) PID Handler ($ppidnumber)->($pidnumber)\n");
        my $scpe = Net::SCP::Expect->new(host=>"$host", user=>"$user", password=>"$pass", port=>"$port");
       	$scpe->scp("$file","$dstp") or  logmsg("[AGENT($AGENT_VARS_GLOB::countexec) | transfer_file    ]     ERROR, Unable to transfer ($host:$port|$user|****|$dstp|$file)\n");
}
##############################################################################################################################
sub decvtoip
{
        my $dec = shift;
        $dec = inet_ntoa pack q/N/,$dec;
        $dec =~ /([0-9]*)\.([0-9]*)\.([0-9]*)\.([0-9]*)/;
        return "$4.$3.$2.$1";
}
##############################################################################################################################
sub iptodecv
{
        my $ip = shift;
        $ip =~ /([0-9]*)\.([0-9]*)\.([0-9]*)\.([0-9]*)/;
        $ip =  "$4.$3.$2.$1";
        my $dec = unpack(q/N/,inet_aton($ip));
        return "$dec";
}
##############################################################################################################################
sub logmsg()
{
        my $msg= shift;
        (my $sec,my $min,my $hour,my $mday,my $mon,my $year,my $wday,my $yday,my $isdst)=localtime(time);
        printf LOGFILE_FD "[%4d-%02d-%02d %02d:%02d:%02d] - %s",$year+1900,$mon+1,$mday,$hour,$min,$sec,$msg;
}
