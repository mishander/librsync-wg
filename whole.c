/*= -*- c-basic-offset: 4; indent-tabs-mode: nil; -*-
 *
 * librsync -- the library for network deltas
 * $Id$
 *
 * Copyright (C) 2000, 2001 by Martin Pool <mbp@samba.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

                              /*
                               | Is it possible that software is not
                               | like anything else, that it is meant
                               | to be discarded: that the whole point
                               | is to always see it as a soap bubble?
                               |        -- Alan Perlis
                               */



#include <config.h>

#include <assert.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "librsync.h"

#include "trace.h"
#include "fileutil.h"
#include "sumset.h"
#include "job.h"
#include "buf.h"
#include "whole.h"
#include "util.h"

extern Rollsum rs_cp;
const char * str_mn = "E6DF329D-C564-4FE9-ABB2-E7975B5D1479";
/**
 * Run a job continuously, with input to/from the two specified files.
 * The job should already be set up, and must be free by the caller
 * after return.
 *
 * Buffers of ::rs_inbuflen and ::rs_outbuflen are allocated for
 * temporary storage.
 *
 * \param in_file Source of input bytes, or NULL if the input buffer
 * should not be filled.
 *
 * \return RS_DONE if the job completed, or otherwise an error result.
 */
rs_result
	rs_whole_run(rs_job_t *job, FILE *in_file, FILE *out_file, int * curr_bytes, int * nStopFlag)
{
    rs_buffers_t    buf;
    rs_result       result;
    rs_filebuf_t    *in_fb = NULL, *out_fb = NULL;

    if (in_file)
        in_fb = rs_filebuf_new(in_file, rs_inbuflen);

    if (out_file)
        out_fb = rs_filebuf_new(out_file, rs_outbuflen);

    result = rs_job_drive(job, &buf,
                          in_fb ? rs_infilebuf_fill : NULL, in_fb,
		out_fb ? rs_outfilebuf_drain : NULL, out_fb,curr_bytes,nStopFlag);

    if (in_fb)
        rs_filebuf_free(in_fb);

    if (out_fb)
        rs_filebuf_free(out_fb);

    return result;
}



/**
 * Generate the signature of a basis file, and write it out to
 * another.
 *
 * \param new_block_len block size for signature generation, in bytes
 *
 * \param strong_len truncated length of strong checksums, in bytes
 *
 * \sa rs_sig_begin()
 */
rs_result
	rs_sig_file(FILE *old_file, FILE *sig_file, size_t new_block_len, size_t strong_len, rs_stats_t *stats,int * curr_bytes, int * nStopFlag)
{
    rs_job_t        *job;
    rs_result       r;

    job = rs_sig_begin(new_block_len, strong_len);
	r = rs_whole_run(job, old_file, sig_file,curr_bytes,nStopFlag);
    if (stats)
        memcpy(stats, &job->stats, sizeof *stats);
    rs_job_free(job);

    return r;
}


/**
 * Load signatures from a signature file into memory.  Return a
 * pointer to the newly allocated structure in SUMSET.
 *
 * \sa rs_readsig_begin()
 */
rs_result
	rs_loadsig_file(FILE *sig_file, rs_signature_t **sumset, rs_stats_t *stats,int * curr_bytes, int * nStopFlag)
{
    rs_job_t            *job;
    rs_result           r;

    job = rs_loadsig_begin(sumset);
	r = rs_whole_run(job, sig_file, NULL, curr_bytes, nStopFlag);
    if (stats)
        memcpy(stats, &job->stats, sizeof *stats);
    rs_job_free(job);

    return r;
}



rs_result
	rs_delta_file(rs_signature_t *sig, FILE *new_file, FILE *delta_file, rs_stats_t *stats,int * curr_bytes, int * nStopFlag)
{
    rs_job_t            *job;
    rs_result           r;

    job = rs_delta_begin(sig);

	r = rs_whole_run(job, new_file, delta_file,curr_bytes,nStopFlag);

    if (stats)
        memcpy(stats, &job->stats, sizeof *stats);

    rs_job_free(job);

    return r;
}



rs_result rs_patch_file(FILE *basis_file, FILE *delta_file, FILE *new_file,
						rs_stats_t *stats,int * curr_bytes, int * nStopFlag)
{
    rs_job_t            *job;
    rs_result           r;
	Rollsum rs_orig;
	int isNewFormat;

	int len = 0;
	int read_count =0;
	int buf_len = 16000;
	unsigned char *buf = (unsigned char *) malloc((sizeof(unsigned char)) * buf_len);
	char cbuf[37];
	int ch_str = 0;
   	RollsumInit(&rs_orig);
	memset(buf,0,buf_len);
	fseek(delta_file, -strlen(str_mn), SEEK_END);
	len = fread(cbuf,sizeof *cbuf,strlen(str_mn),delta_file);
	cbuf[36] = '\0';
	if (len > 0)
	{
		ch_str = strcmp(cbuf,str_mn);
	}
	else
	{
	    ch_str = 0;
	}
	if (ch_str)
	{
	  	isNewFormat = 0;
	}
	else
	{
	    isNewFormat = 1;
		fseek(delta_file, -(sizeof(Rollsum)+strlen(str_mn)), SEEK_END);
		fread(&rs_orig,sizeof(Rollsum),1,delta_file);
	}
	rewind(delta_file);
    job = rs_patch_begin(rs_file_copy_cb, basis_file);

	r = rs_whole_run(job, delta_file, new_file,curr_bytes,nStopFlag);
    
	if (isNewFormat && (*nStopFlag == 0) && (r == RS_DONE))
	if ((rs_cp.count != rs_orig.count) || (rs_cp.s1 != rs_orig.s1) || (rs_cp.s2 != rs_orig.s2)  )
	{
		r = RS_INPUT_ENDED;
	}
    if (stats)
        memcpy(stats, &job->stats, sizeof *stats);

	free(buf);
    rs_job_free(job);

    return r;
}
int DllExport applyPatch(const wchar_t * sSourceFilePathName, const wchar_t * sDestFilePathName, const wchar_t * sDiffFilePathName, int * curr_bytes_decoded,int * nStopFlag)
{
	rs_result result;
	FILE * delta_file;
	FILE * basis_file ;
	FILE * new_file;
	rs_stats_t stats;
	int err = _wfopen_s(&basis_file,sSourceFilePathName, L"rb");
	if(0 != err)
	{
		return (err+200);
	}
	err = _wfopen_s(&delta_file,sDiffFilePathName, L"rb");
	if(0 != err)
	{
		fclose(basis_file);
		return (err+400);
	}
	err = _wfopen_s(&new_file,sDestFilePathName, L"wb");
	if(0 != err)
	{
		fclose(basis_file);
		fclose(delta_file);
		return (err+300);
	}
	result = rs_patch_file(basis_file, delta_file, new_file, &stats, curr_bytes_decoded, nStopFlag);
	fclose(basis_file);
	fclose(delta_file);
	fclose(new_file);
	return result;
}
int DllExport makePatch(const wchar_t * sSourceFilePathName, const wchar_t * sDestFilePathName, const wchar_t * sDiffFilePathName,const wchar_t * sSigFileName, int block_len, int strong_len, int * curr_bytes_encoded,int * nStopFlag)
{
	FILE * basis_file ;
	FILE * delta_file;
	FILE * new_file;
	FILE * sig_file;
	rs_stats_t stats;
	rs_result rr;
	rs_signature_t * rs_sig;
	FILE * sig_fileR;
	int len = 0;
	int BLOCK_SIZE = 16000;
	int read_count =0;
	int buf_len = BLOCK_SIZE;
	Rollsum rs_basis;
	int err = 0;
	err = _wfopen_s(&basis_file,sSourceFilePathName, L"rb");
	if(0 != err)
	{
		return (err+200);
	}
	err = _wfopen_s(&delta_file,sDiffFilePathName, L"wb");
	if(0 != err)
	{
		fclose(basis_file);
		return (err+400);
	}
	err = _wfopen_s(&new_file,sDestFilePathName, L"rb");
	if(0 != err)
	{
		fclose(basis_file);
		fclose(delta_file);
		return (err+300);
	}
	err = _wfopen_s(&sig_file,sSigFileName, L"wb");
	if(0 != err)
	{
		fclose(basis_file);
		fclose(delta_file);
		fclose(new_file);
		return (err+100);
	}
	rr =rs_sig_file(basis_file,sig_file, block_len, strong_len,&stats, curr_bytes_encoded, nStopFlag);
	fclose(sig_file);
	err = _wfopen_s(&sig_fileR,sSigFileName, L"rb");
	if(0 != err)
	{
		fclose(basis_file);
		fclose(delta_file);
		fclose(new_file);
		return (err+100);
	}
	rr = rs_loadsig_file(sig_fileR,&rs_sig,&stats, curr_bytes_encoded, nStopFlag);
	rr = rs_build_hash_table(rs_sig);
	rr = rs_delta_file(rs_sig,new_file,delta_file,&stats, curr_bytes_encoded, nStopFlag);
	{
	unsigned char *buf = (unsigned char *) malloc((sizeof(unsigned char)) * buf_len);
	RollsumInit(&rs_basis);
	rewind(new_file);
	while( 0 != ( read_count = fread( buf, sizeof *buf, buf_len, new_file )))
		RollsumUpdate( &rs_basis,buf,read_count );
	rs_free_sumset(rs_sig);
	fwrite(&rs_basis,sizeof(Rollsum),1,delta_file);
	fwrite(str_mn,sizeof *str_mn,strlen(str_mn),delta_file);
	free(buf);
	}
	fclose(basis_file);
	fclose(delta_file);
	fclose(new_file);
	fclose(sig_file);
	fclose(sig_fileR);
	return rr;
}