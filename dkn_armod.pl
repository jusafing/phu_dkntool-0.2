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
# dkn_armod.pl
# DKN ProcessTool - Structured Traffic Analysis Module (ARGUS Module)
############################################################################
use strict;
use POSIX 'strftime';
use File::Copy;
use File::Path;
use DKNCONF;
############################################################################
############################################################################
getdata();
############################################################################
############################################################################
sub getdata()
{
	my @ifaces	= split(" ",$CONFIG_VARS::argus_ifaces);
	open(LOGFILE_FD,"+>>$CONFIG_VARS::argus_logfile") || die "ERROR, ARMOD log file could not be created [$CONFIG_VARS::argus_logfile]\n";
        logmsg("*****************************************************************\n")  ;
        logmsg("******* [STRUCTURED TRAFFIC ANALYSIS MODULE - ARGUS DATA] *******\n")  ;
        logmsg("*****************************************************************\n\n");
	logmsg("[ARMOD | getdata       ] STARTING ARGUS MODULE\n");
	(my $gsec,my $gmin,my $ghour,my $gmday,my $gmon,my $gyear,my $gwday,my $gyday,my $gisdst)=localtime(time);
	$gyear += 1900;
	my $gdate 	= sprintf("%4d-%02d-%02dT%02d:%02d:%02d",$gyear,$gmon+1,$gmday,$ghour,$gmin,$gsec);
	my $date	= strftime('%Y%m%d-%H', localtime);
	my $outdir 	= "$CONFIG_VARS::argus_dir/$date"; 
	my $argusdatafile;
	my $arguscapfile;
	unless ( -d $outdir )
	{
		logmsg("[ARMOD | getdata       ] |- Creating ARGUS directory ($outdir)\n");
		mkpath $outdir || logmsg("[ARMOD | getdata       ]   ERROR, could not be created ($outdir)\n") unless (-d $outdir);
	}
	foreach my $iface (@ifaces)
	{
		argus_stop($iface);
		if ($CONFIG_VARS::argus_cap == 1)
		{
			logmsg("[ARMOD | getdata       ] |- Creating Argus file ... ");
			`/usr/sbin/argus -r $CONFIG_VARS::argus_capfile -w $CONFIG_VARS::argus_datafile.$iface && echo "OK SHELL" >> $CONFIG_VARS::argus_logfile`;
			logmsg("[ARMOD | getdata       ] |- Moving Argus cap file ($CONFIG_VARS::argus_capfile.$iface) to ($outdir/$date.cap.$iface)\n");
			rename("$CONFIG_VARS::argus_capfile.$iface","$outdir/$date.cap.$iface") || logmsg("[ARMOD | getdata       ]   ERROR, could not be copied ($CONFIG_VARS::argus_capfile.$iface) to ($outdir/$date.cap.$iface)\n");
			$arguscapfile="$outdir/$date.cap.$iface";
		}
		logmsg("[ARMOD | getdata       ] |- Moving Argus dat file ($CONFIG_VARS::argus_datafile.$iface) to ($outdir/$date.argus.$iface)\n");
		rename("$CONFIG_VARS::argus_datafile.$iface","$outdir/$date.argus.$iface") || logmsg("[ARMOD | getdata       ]   ERROR, could not be copied ($CONFIG_VARS::argus_datafile.$iface) to ($outdir/$date.argus.$iface)\n");
		$argusdatafile = "$outdir/$date.argus.$iface";
		argus_start($iface);
		argus_data($argusdatafile,$outdir,$iface);
	}
	logmsg("[ARMOD | getdata       ] PROCESS COMPLETED\n");
	close(LOGFILE_FD);
}
############################################################################
sub argus_data()
{
	my $argusfile 	= shift;
	my $outdir	= shift;
	my $iface	= shift;
	logmsg("[ARMOD | argus_data    ] |- GENERATING ARGUS DATA\n");
	logmsg("[ARMOD | argus_data    ]      |- Creating racount file           ... ");
	`racount -r $argusfile > $outdir/stats.dat.$iface && echo "OK" >> $CONFIG_VARS::argus_logfile`;
	logmsg("[ARMOD | argus_data    ]      |- Creating hosts file             ... ");
	`rahosts -r $argusfile > $outdir/hosts.dat.$iface && echo "OK" >> $CONFIG_VARS::argus_logfile`;
	logmsg("[ARMOD | argus_data    ]      |- Creating traffic sessions file  ... ");
	`ra -n -r   $argusfile -s saddr daddr dport proto | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | uniq -c| sort -nr > $outdir/sessions.dat.$iface && echo "OK" >> $CONFIG_VARS::argus_logfile`;
	logmsg("[ARMOD | argus_data    ]      |- Creating traffic sessions of defined rules ->\n");
	open(RULES_FD,"<$CONFIG_VARS::rules_file") || logmsg("[ARMOD | argus_data    ]         |- ERROR, rules file could not be readed ($CONFIG_VARS::rules_file)\n");
       	while(<RULES_FD>)
        {
	        chomp();
		next if ( $_ =~ /^#/ );
                next unless ( $_ =~ /.*\|.*\|.*\|.*\|.*/ );
		argus_radata_rules("$_",$argusfile,$outdir,$iface);
	}
	close(RULES_FD);
}
############################################################################
sub argus_radata_rules()
{
	my $rule	= shift;
	my $argusfile 	= shift;
	my $outdir	= shift;
	my $iface	= shift;
	my @rule_line	= split(/\|/,$rule);
	my $msg		= $rule_line[0];
	   $msg 	= ~ s/ /_/g;
	my $proto	= lc($rule_line[1]);
	my $port	= $rule_line[2];
	my $regexpayload= $rule_line[3];
	logmsg("[ARMOD | argus_radata_r]         |- Creating stats REGEX PAYLOAD for rule <$proto-$port-[$regexpayload]>  ... ");
	`ra -r $argusfile -s "saddr daddr dport suser:50 " -n -e "$regexpayload" - $proto and dst port $port | sort | uniq -c | sort -nr > $outdir/sessions_$msg-$proto-$port-string.dat.$iface && echo "OK" >> $CONFIG_VARS::argus_logfile`;
	logmsg("[ARMOD | argus_radata_r]         |- Creating stats GENERAL for rule <$proto-$port>  ... ");
	`ra -r $argusfile -n -s saddr daddr dport proto - $proto and dst port $port | sort | uniq -c | sort -nr > $outdir/sessions_$msg-$proto-$port.dat.$iface && echo "OK" >> $CONFIG_VARS::argus_logfile`;
}
############################################################################
sub argus_stop()
{
	my $iface	= shift;
	my $pid		= `ps aux | grep argus | grep $iface | grep -v grep | awk '{print \$2}'| head -1`;
	chomp($pid)	;
	logmsg("[ARMOD | argus_stop    ] |- Stopping ARGUS daemon iface [$iface] pid [$pid] ... ");
	`kill -9 $pid && echo "OK" >> $CONFIG_VARS::argus_logfile`;
}
############################################################################
sub argus_start()
{
	my $iface	= shift;
	logmsg("[ARMOD | argus_start   ] |- Starting ARGUS daemon iface [$iface] ... ");
	`/usr/sbin/argus -i $iface -w $CONFIG_VARS::argus_datafile.$iface -d && echo "OK" >> $CONFIG_VARS::argus_logfile`;
}
############################################################################
sub logmsg()
{
        my $msg= shift;
        (my $sec,my $min,my $hour,my $mday,my $mon,my $year,my $wday,my $yday,my $isdst)=localtime(time);
        printf LOGFILE_FD "[%4d-%02d-%02d %02d:%02d:%02d] - %s",$year+1900,$mon+1,$mday,$hour,$min,$sec,$msg;
}
############################################################################
