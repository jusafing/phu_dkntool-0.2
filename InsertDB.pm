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
# dkn_agent.pl
# DKN ProcessTool - Module for DB data insertion of DKN pipe format.
############################################################################
############################################################################
use strict;
package CONFIG_VARS;
our $countexec	= 0;
our $dbconn;
##############################################################################################################################
package InsertDB;
use DBI;
use DateTime;
use Archive::Tar;
use File::Path;
use DKNCONF;
##############################################################################################################################
sub insert
{
	my $input 	= shift;
	my $logfile	= shift;
	my $type	= shift;
	$CONFIG_VARS::dbconn  = DBI->connect("DBI:Pg:dbname=$CONFIG_VARS::psql_db; host=$CONFIG_VARS::psql_host; port=$CONFIG_VARS::psql_port", "$CONFIG_VARS::psql_usr", "$CONFIG_VARS::psql_pwd");
	open(LOGFILE_FD,"+>>$logfile") || die "ERROR, no se pudo abrir el archivo de LOG [$logfile]\n";
	if ( $type eq "FILE" )
	{
		logmsg("[INSERT($CONFIG_VARS::countexec) | insert             ] READING FILE  [$input]\n");
		logmsg("[INSERT($CONFIG_VARS::countexec) | insert             ]     Connecting to DB [$CONFIG_VARS::psql_host|$CONFIG_VARS::psql_db|$CONFIG_VARS::psql_usr]\n");
		open(FILE,"<$input") or die "ERROR, The file [$input] could not be opened\n";
		while(<FILE>)
		{
			chomp();
			next unless($_ =~ m/.+/);
			insert_datadb("$_");
			$CONFIG_VARS::countexec++;
		}

        	logmsg("---------------------------------------------\n");
	        logmsg("SUMMARY --> ($CONFIG_VARS::countexec) incidents have been stored\n");
	}
	elsif ( $type eq "DATA" )
	{
		insert_datadb("$input");
	}
	$CONFIG_VARS::dbconn->disconnect();
	close(LOGFILE_FD);
}
##############################################################################################################################
sub insert_datadb
{
        my $inc_data     = shift;
        my @data=split(/\|/,$inc_data);
        my $inc_device   = $data[0];
        my $inc_count    = $data[1];
        my $inc_proto    = $data[2];
        my $inc_sip      = $data[3];
        my $inc_fts      = $data[11];
        my $inc_lts      = $data[10];
        my $inc_type     = $data[12];
        my $inc_det_file = $data[13];
        my $inc_tgz_file = $data[14];
#	$inc_det_file	 =~ s/.*events_connections/$CONFIG_VARS::newpath/g;
#	$inc_tgz_file	 =~ s/.*events_connections/$CONFIG_VARS::newpath/g;
	my $tmpdir	 = $inc_tgz_file;
	my @payloadsf;
	if (-e $inc_tgz_file)
	{
		$tmpdir		 =~ s/\.tgz//g;
		$tmpdir 	 = "/tmp/$tmpdir";
		logmsg("[INSERT($CONFIG_VARS::countexec) | insert_datadb      ]     Making new tmp directory ($tmpdir)\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
		mkpath("$tmpdir") unless (-d $tmpdir) || logmsg("[INSERT($CONFIG_VARS::countexec) | insert_datadb      ]     ERROR, tmp directory ($tmpdir) could not be created\n");
		xtractar($inc_tgz_file,$tmpdir);
		@payloadsf 	 = getlist("$inc_tgz_file","$tmpdir");
	}
	else
	{
		logmsg("[INSERT($CONFIG_VARS::countexec) | get_list           ]     INFO There is not file to xtract($inc_tgz_file)\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
	}
        my $inc_idinc    = db_insert_inc($inc_fts,$inc_count,$inc_type);
        db_insert_det($inc_idinc,$inc_proto,$inc_device,$inc_lts);
        db_insert_ip($inc_idinc,$inc_sip);
	logmsg(">>>>>>>>>>>>>>>>> FTS [$inc_device] <<<<<<<<<<<<<<<<<\n");
##	unless ($inc_device =~ m/.*-.*-.*T.*:.*:.*/)
	unless ($inc_device =~ m/dkn.*/)
	{
	        db_insert_ex_tformat($inc_idinc,$inc_det_file);
	}
	else
	{
	        db_insert_ex_epoch($inc_idinc,$inc_det_file);
	}
        db_insert_payload($inc_idinc,@payloadsf);
	if (-d $tmpdir && -e $inc_tgz_file)
	{
		logmsg("[INSERT($CONFIG_VARS::countexec) | insert_datadb      ]     Deleting temporal directory ($tmpdir)\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
		rmtree("$tmpdir")
	}
}
##############################################################################################################################
sub xtractar()
{
        chomp(my $filex = shift);
        chomp(my $dstd  = shift);
        logmsg("[INSERT($CONFIG_VARS::countexec) | xtractar           ]     Extracting tgz file ($filex) on ($dstd)\n");
        my $tar   = Archive::Tar->new;
        $tar->read($filex);
        $tar->setcwd($dstd);
        $tar->extract() || logmsg("[INSERT($CONFIG_VARS::countexec) | xtractar           ]     ERROR, Couldn't extract tgz file ($filex) on ($dstd)\n");
}
##############################################################################################################################
sub getlist()
{
        chomp(my $file = shift);
	chomp(my $path	= shift);
	logmsg("[INSERT($CONFIG_VARS::countexec) | get_list           ]     Getting payloads names of ($file)\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
        my $tar         = Archive::Tar->new;
        my $names;
        $tar->read($file);
        my @list        = $tar->list_files();
        while(<@list>)
        {
                chomp();
		my $newf = "$path/$_";
                $names .= " $newf";
        }
        return $names;
}
##############################################################################################################################
sub db_insert_det()
{
        my $idinc       = shift;
        my $proto       = shift;
        my $device      = shift;
        my $lts	    	= shift;
        my $idproto     = db_getregid("protocolos","idprotocolos","nombre",$proto);
        my $iddevice    = db_getregid("dispositivos","iddispositivos","nombre",$device);
        logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_det      ]     Saving DETAILS info of incident [$idinc]\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
        my $query       = $CONFIG_VARS::dbconn->prepare(q{INSERT INTO detalles(incidentes_idincidentes,dispositivos_iddispositivos,protocolos_idprotocolos,time_f) VALUES (?, ?, ?, ?)}) or logmsg("Detalles INSERT ERROR");
        $query->execute($idinc,$iddevice,$idproto,$lts) || logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_det      ]     ERROR, DETAILS Insert execute [INSERT INTO detalles(incidentes_idincidentes,dispositivos_iddispositivos,protocolos_idprotocolos,time_f) VALUES ($idinc,$iddevice,$idproto,$lts)]\n");
        $query->finish;
}
##############################################################################################################################
sub db_insert_inc()
{
        my $timestamp	= shift;
        my $count       = shift;
        my $type        = shift;
        my $idtype      = db_getregid("tipos","idtipos","nombre",$type);
	logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_inc      ]     IDTYPE: [$idtype] TYPE [$type]\n");
        my $query       = $CONFIG_VARS::dbconn->prepare(q{INSERT INTO incidentes(tipos_idtipos,time,contador_eventos) VALUES (?, ?, ?) RETURNING idincidentes}) or logmsg("Incidentes INSERT ERROR");
        $query->execute($idtype,$timestamp,$count) || logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_inc      ]     ERROR, INCIDENT Insert execute [INSERT INTO incidentes(tipos_idtipos,time,contador_eventos) VALUES ($idtype,$timestamp,$count)]\n");
        my $idincidentes=$query->fetchrow_array();
        logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_inc      ]     New INCIDENT has been stored [$idincidentes]\n") if($idincidentes =~ m/[0-9]+/);
        $query->finish;
        return $idincidentes;
}
##############################################################################################################################
sub db_insert_ip()
{
        my $idinc       = shift;
        my $sip         = shift;
        logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_ip       ]     Saving IP      info of incident [$idinc]\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
        my $query       = $CONFIG_VARS::dbconn->prepare(q{INSERT INTO ip(incidentes_idincidentes,ip_o) VALUES (?, ?)}) or logmsg("IP INSERT ERROR");
        $query->execute($idinc,$sip) || logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_ip       ]     ERROR, IP Insert execute [INSERT INTO ip(incidentes_idincidentes,ip_o) VALUES ($idinc,$sip)]\n") ;
        $query->finish;
}
##############################################################################################################################
sub db_insert_ex_tformat()
{
        my $idinc       = shift;
        my $det_file    = shift;
        logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_ex_tforma]     Saving EXTRA   info of incident [$idinc] with [$det_file]\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
        open(DETFILE_FD,"<$det_file") || logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_ex_tforma]     ERROR, DET file ($det_file) could not be opened\n");
        while(<DETFILE_FD>)
        {
                chomp();
                my @extra       = split(/\|/,$_);
                my $timestamp   = $extra[0];
                my $sip         = $extra[1];
                my $sport       = $extra[2];
                my $dip         = $extra[3];
                my $dport       = $extra[4];
                my $hash        = $extra[5];
                my $mailpayl    = $extra[6];
                my $urlpayl     = $extra[7];
                my $domainpayl  = $extra[8];
                my $ippayl      = $extra[9];
                my $pattpayl    = $extra[10];
                my $query       = $CONFIG_VARS::dbconn->prepare(q{INSERT INTO extras(incidentes_idincidentes,campo1,campo2,campo3,campo4,campo5,campo6,campo7,campo8,campo9,campo10,campo11) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)}) or logmsg("EXTRAS INSERT ERROR");
                $query->execute($idinc,$timestamp,$sip,$sport,$dip,$dport,$hash,$mailpayl,$urlpayl,$domainpayl,$ippayl,$pattpayl) || logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_ex_tforma]     ERROR, EXTRAS Insert execute [INSERT INTO extras(incidentes_idincidentes,campo1,campo2,campo3,campo4,campo5,campo6,campo7,campo8,campo9,campo10,campo11) VALUES ($idinc,$timestamp,$sip,$sport,$dip,$dport,$hash,$mailpayl,$urlpayl,$domainpayl,$ippayl,$pattpayl)]\n");
                $query->finish;
        }
        close(DETFILE_FD)
}
##############################################################################################################################
sub db_insert_ex_epoch()
{
        my $idinc       = shift;
        my $det_file    = shift;
        logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_ex_epoch ]     Saving EXTRA   info of incident [$idinc] with [$det_file]\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
        open(DETFILE_FD,"<$det_file") || logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_ex_epoch ]     ERROR, DET file ($det_file) could not be opened\n");
        while(<DETFILE_FD>)
        {
                chomp();
                my @extra       = split(/\|/,$_);
                my $epochts     = $extra[0];
                my $sip         = $extra[1];
                my $sport       = $extra[2];
                my $dip         = $extra[3];
                my $dport       = $extra[4];
                my $hash        = $extra[5];
                my $mailpayl    = $extra[6];
                my $urlpayl     = $extra[7];
                my $domainpayl  = $extra[8];
                my $ippayl      = $extra[9];
                my $pattpayl    = $extra[10];
                my $dt          = DateTime->from_epoch( epoch => $epochts );
                my $timestamp   = $dt->ymd."T".$dt->hms;
                my $query       = $CONFIG_VARS::dbconn->prepare(q{INSERT INTO extras(incidentes_idincidentes,campo1,campo2,campo3,campo4,campo5,campo6,campo7,campo8,campo9,campo10,campo11) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)}) or logmsg("EXTRAS INSERT ERROR");
                $query->execute($idinc,$timestamp,$sip,$sport,$dip,$dport,$hash,$mailpayl,$urlpayl,$domainpayl,$ippayl,$pattpayl) || logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_ex_epoch ]     ERROR, EXTRAS Insert execute [INSERT INTO extras(incidentes_idincidentes,campo1,campo2,campo3,campo4,campo5,campo6,campo7,campo8,campo9,campo10,campo11) VALUES ($idinc,$timestamp,$sip,$sport,$dip,$dport,$hash,$mailpayl,$urlpayl,$domainpayl,$ippayl,$pattpayl)]\n");
                $query->finish;
        }
        close(DETFILE_FD)
}
##############################################################################################################################
sub db_insert_payload()
{
        my $idinc       = shift;
        my @payloads    = shift;
	my $numpay 	= @payloads;
	return if ($numpay == 1 and $payloads[0] eq '');
        logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_payload  ]     Saving PAYLOAD info of incident [$idinc] with [@payloads]\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
        while(<@payloads>)
        {
                my $pathpayload = $_;
		my @path        = split("/",$pathpayload);
		my $numdir	= @path;
		   $numdir	--;
		my $filename	= $path[$numdir];
                my $regpayload  = db_getregid("payload","idpayload","md5",$filename);
                unless($regpayload =~ m/[0-9]+/)
                {
                        logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_payload  ]       Saving payload file ($pathpayload) HASH: ($filename) of incident [$idinc]\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
                        my $query = $dbconn->prepare(q{INSERT INTO payload(md5,payload) VALUES (?, ?) RETURNING idpayload}) or logmsg("PAYLOAD INSERT ERROR");
                        my $oid = $dbconn->func($pathpayload,'lo_import');
                        $query->execute($filename,$oid) || logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_payload  ]       ERROR, PAYLOAD Insert execute [INSERT INTO payload(md5,payload) VALUES ($filename,FUNC_lo_import($pathpayload))]\n");
                        $regpayload = $query->fetchrow_array();
        	        $query->finish;
			if ($regpayload =~ m/[0-9]+/)
			{
	                        logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_payload  ]       New payload has been stored with id [$regpayload]\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
			}
                }
                logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_payload  ]       New registry of incident-payload has been stored with [$idinc]-[$regpayload]\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
		my $query = $dbconn->prepare(q{INSERT INTO payload_incidente(incidentes_idincidentes,payload_idpayload) VALUES (?, ?)}) or logmsg("PAYLOAD_INCIDENT INSERT ERROR\n");
                $query->execute($idinc,$regpayload) || logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_payload  ]       ERROR, PAYLOAD_INCIDENT Insert execute [INSERT INTO payload_incidente(incidentes_idincidentes,payload_idpayload) VALUES($idinc,$regpayload)]\n");
                $query->finish;
#		if (-e $pathpayload)
#		{
#       		logmsg("[INSERT($CONFIG_VARS::countexec) | db_insert_payload  ]       Deleting original payload file from file system [$pathpayload]\n") if ($CONFIG_VARS::DEBUG_MODE == 1);
#			rename("$pathpayload","$");
#		}
        }
}
##############################################################################################################################
sub db_getregid()
{
        my $tablename   = shift;
        my $idcolumn    = shift;
        my $descolumn   = shift;
        my $desc        = shift;
        my $prequery    = "SELECT $idcolumn from $tablename where $descolumn=?";
        my $query       = $CONFIG_VARS::dbconn->prepare($prequery) or logmsg("Could not get id from $tablename|$idcolumn|$descolumn ($desc)\n");
        $query->execute($desc)  || logmsg("[INSERT($CONFIG_VARS::countexec) | db_getregid      ]     ERROR, SELECT execute [SELECT $idcolumn from $tablename where $descolumn='$desc']\n");
        my ($result)    = $query->fetchrow_array();
        $query->finish;
        return $result;
}
##############################################################################################################################
sub logmsg()
{
        my $msg= shift;
        (my $sec,my $min,my $hour,my $mday,my $mon,my $year,my $wday,my $yday,my $isdst)=localtime(time);
        printf LOGFILE_FD "[%4d-%02d-%02d %02d:%02d:%02d] - %s",$year+1900,$mon+1,$mday,$hour,$min,$sec,$msg;
}
##############################################################################################################################
##############################################################################################################################
1;
