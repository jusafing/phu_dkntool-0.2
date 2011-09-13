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
# dkn_snmod.pl
# DKN ProcessTool - Structured Traffic Analysis Module. SNORT Module
############################################################################
use strict;
use POSIX 'strftime';
use File::Copy;
use File::Path;
use InsertDB;
use DKNCONF;
############################################################################
getdata();
############################################################################
sub getdata()
{
	my $date	= strftime('%Y%m%d-%H', localtime);
	my $outdir 	= "$CONFIG_VARS::snort_dir/$date"; 
	open(LOGFILE_FD,"+>>$CONFIG_VARS::snort_logfile") || die "ERROR, SNMOD log file could not be created [$CONFIG_VARS::snort_logfile]\n";
        logmsg("*****************************************************************\n")  ;
        logmsg("************* [STRUCTURED TRAFFIC ANALYSIS MODULE] **************\n")  ;
        logmsg("*****************************************************************\n\n");
	logmsg("[SNMOD | getdata       ] STARTING SNORT MODULE\n");
	logmsg("[SNMOD | getdata       ] |- Creating Snort directory ($outdir) ->\n");
	mkpath "$outdir"   || logmsg("[SNMOD | getdata       ]    ERROR, could not be created ($outdir)\n")    unless (-d "$outdir");
	if ( $CONFIG_VARS::snort_input eq "alert" )
	{
		logmsg("[SNMOD | getdata       ] |- Input method ($CONFIG_VARS::snort_input) selected\n");
		logmsg("[SNMOD | getdata       ] |- Moving ($CONFIG_VARS::snort_alertfile) to ($outdir/alert)\n");
		copy("$CONFIG_VARS::snort_alertfile","$outdir/alert")   || logmsg("[SNMOD | getdata       ]    ERROR file ($CONFIG_VARS::snort_alertfile) could not be copied to ($outdir/alert)\n");
		open(FOO,">$CONFIG_VARS::snort_alertfile") || logmsg("[SNMOD | getdata       ]    ERROR file ($CONFIG_VARS::snort_alertfile) could not be written\n");
		print FOO "\n";
		close(FOO);
		getpipe_alert("$outdir");
	}
	elsif ( $CONFIG_VARS::snort_input eq "snortdb" )
	{
		logmsg("[SNMOD | getdata       ] |- Input method ($CONFIG_VARS::snort_input) selected\n");
		getpipe_snortdb();
	}
	else
	{
		logmsg("[SNMOD | getdata       ] |- ERROR, invalid input method ($CONFIG_VARS::snort_input)\n");
	}
	snort_data($outdir);
	close(LOGFILE_FD);
	InsertDB::insert("$outdir/incidents_sn.log","$CONFIG_VARS::snort_logfile","FILE");
}
############################################################################
sub getpipe_alert()
{
	my $outdir	= shift;
	my $alertfile	= "$outdir/alert";
	my $outfile	= "$outdir/alert.pipe";
	logmsg("[SNMOD | getpipe_alert ] |- Creating SNORT pipe file ($alertfile)\n");
	open (ARCHIVO,"<$alertfile") || logmsg("[SNMOD | getpipe_alert  ]    |- ERROR, could not be opened  ($alertfile)\n");
	open (DATOS,">$outfile")    || logmsg("[SNMOD | getpipe_alert  ]    |- ERROR, could not be written ($outfile)\n");
	while (<ARCHIVO>)
	{
        	chomp;
	        my $linea = $_;
        	if($linea =~ /^$/)
	        {
        	        print DATOS "\n$linea";
	        }
        	else
	        {
        	        $linea=$linea." | ";
                	print DATOS $linea;
	        }
	}
	close(ARCHIVO);
	close(DATOS);
}
############################################################################
sub getpipe_snortdb()
{
	print "BLA";
}
############################################################################
sub snort_data()
{
	my $outdir	= shift;
	my $pipefile	= "$outdir/alert.pipe";
	my @alertasok	;
	my %alert_name	;
	my %alert_srcip	;
	my %alert_dstip	;
	my %alert_srcport;
	my %alert_dstport;
	my %alert_class	;
	my %alert_atthst;
	my %data	;
	my %detfile	;
	(my $gsec,my $gmin,my $ghour,my $gmday,my $gmon,my $gyear,my $gwday,my $gyday,my $gisdst)=localtime(time);
	$gyear += 1900;
	my $gdate = sprintf("%4d-%02d-%02dT%02d:%02d:%02d",$gyear,$gmon+1,$gmday,$ghour,$gmin,$gsec);
	open(ALERTA,"<$pipefile") || logmsg("[SNMOD | snort_data    ]         |- ERROR, The file could not be opened ($pipefile)\n");
	while (<ALERTA>)
	{
		chomp;
		next if ($_ =~ m/^$/);
		my @alert_line     =  split(/\|/,$_);
		my $alert_name     =  "$alert_line[0]"; 
	           $alert_name     =~ s/\[\*\*\]//g;
        	   $alert_name     =~ s/\[[0-9]+\:[0-9]+\:[0-9]+\]//g;
        	   $alert_name     =~ s/\(.*\) //;
        	   $alert_name     =~ s/  //g;
		my $infoalert      =  "$alert_name\t$alert_line[1]\t$alert_line[2]\n";
		my @alert_iptmp    = split(" ",$alert_line[2]);
		my @alert_ipsrc    = split(":",$alert_iptmp[1]);
		my @alert_ipdst    = split(":",$alert_iptmp[3]);
		my $alert_time	   = gettime($alert_iptmp[0],$gyear);
		my $alert_class_   = "$alert_line[1]";
		my $alert_ip_src   = "$alert_ipsrc[0]";
		my $alert_ip_dst   = "$alert_ipdst[0]";
		my $alert_port_src = "$alert_ipsrc[1]";
		my $alert_port_dst = "$alert_ipdst[1]";
		my $alert_atta_hst = "$alert_name||$alert_class_||$alert_ip_src||$alert_port_src||$alert_ip_dst||$alert_port_dst";

		$alert_name{$alert_name}++;
		$alert_srcip{$alert_ip_src}++;
		$alert_dstip{$alert_ip_dst}++;
		$alert_srcport{$alert_port_src}++;
		$alert_dstport{$alert_port_dst}++;
		$alert_class{$alert_class_}++;
		$alert_atthst{$alert_atta_hst}++;

        	my @protox	= split(" ",$alert_line[3]);
	        my $proto	= lc($protox[0]);
		my $alert_sname = $alert_name;
		$alert_sname	=~ s/ //g;
		$alert_sname	=~ s/\///g;
        	$data{"$proto|$alert_ipsrc[0]|||||||$gdate|$gdate|$alert_name|$outdir/alert-$proto-$alert_ipsrc[0]-$alert_sname.det||"}++;
		$detfile{"$outdir/alert-$proto-$alert_ipsrc[0]-$alert_sname.det"} .= "$alert_time|$alert_ipsrc[0]|$alert_ipsrc[1]|$alert_ipdst[0]|$alert_ipdst[1]|||||||\n";
	}
	close(ALERTA);
	logmsg("[SNMOD | snort_data    ] |- Creating SNORT inc  file ($outdir/incidents_sn.log)\n");
	foreach my $i (keys%detfile)
	{
		open(DATA,"+>$i") || logmsg("[SNMOD | snort_data    ]         |- ERROR, Unable to write on file ($i)\n");
		print DATA $detfile{$i};
		close(DATA);
	}
	open(DATOS,"+>$outdir/incidents_sn.log") || logmsg("[SNMOD | snort_data    ]         |- ERROR, Unable to write on file ($outdir/incidents_sn.log)\n");
	foreach my $i (keys%data)
	{
        	print DATOS "$CONFIG_VARS::sensorname|$data{$i}|$i\n";

	}
	close(DATOS);
}
############################################################################
sub gettime()
{
	my $datesnort 	= shift;
	my $year	= shift;;
	chomp($datesnort);
	my @array	= split(//, $datesnort);
	$datesnort =~ m/(..)\/(..)-(..):(..):(..).*/;
	my $month	= $1;
	my $day		= $2;
	my $hour	= $3;
	my $min		= $4;
	my $sec		= $5;
	return "$year-$month-$day\T$hour:$min:$sec";
}
############################################################################
sub logmsg()
{
        my $msg= shift;
        (my $sec,my $min,my $hour,my $mday,my $mon,my $year,my $wday,my $yday,my $isdst)=localtime(time);
        printf LOGFILE_FD "[%4d-%02d-%02d %02d:%02d:%02d] - %s",$year+1900,$mon+1,$mday,$hour,$min,$sec,$msg;
}
############################################################################
