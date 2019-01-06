#!/usr/bin/env python3
from __future__ import print_function

import argparse
import sys
import os
import logging
import shutil
import pwd

from security_policy import ASPExtractor, ASPCodec, path_to_firmware_name, AndroidSecurityPolicy
from util.file import directories, chown_recursive, chown_parents

logging.basicConfig(stream=sys.stdout, format="%(levelname)s: %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

"""
Android Policy Extractor
 1. Mount all android file systems
 2. Extract extended attributes (SELinux), capabilities, and DAC information
 3. Capture all SEAndroid policy files
 4. Save to database, including build.prop and other metadata (filepath)
 5. Clean up
"""

def main():
    print("BigMAC Android Policy Extractor")
    print(" by Grant Hernandez (https://hernan.de/z)")
    print("")

    parser = argparse.ArgumentParser()
    parser.add_argument('--vendor', required=True)
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--user', required=True, help="The pwname of a user to chmod extracted policy files to.")
    parser.add_argument('--job-id', help="The job number to enable parallel extraction.")
    parser.add_argument('--force-extract', action='store_true',
                        help='Force an extraction, even if the database exists already')

    parser.add_argument("firmware_image")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not os.access(args.firmware_image, os.R_OK):
        log.error("Firmware image does not exist or is not readable")
        return 1

    if os.geteuid() != 0:
        log.error("""You must be root in order to perform policy extraction.
It requires the use of mount/unmount and reading of root-owned files in mounted filesystems.""")
        return 1

    try:
        output_uid = pwd.getpwnam(args.user).pw_uid
        output_gid = pwd.getpwnam(args.user).pw_gid
    except KeyError:
        log.error("Specified user '%s' not found on system", args.user)

    firmware_name = path_to_firmware_name(args.firmware_image)

    asp = AndroidSecurityPolicy(args.vendor, firmware_name)
    aspc = ASPCodec(asp)

    try:
        log.info("Checking if valid policy is saved...")
        aspc.load()
        asp_exists = True
    except ValueError as e:
        # failed to load policy
        asp_exists = False
        log.warn("Unable to load existing policy: %s", e)

    do_extract = args.force_extract or not asp_exists

    if do_extract:
        if args.force_extract:
            log.warn("Forcing extraction even though %s policy exists", firmware_name)

        if os.access(aspc.results_dir, os.R_OK):
            log.warn("Removing existing policy directory '%s'", aspc.results_dir)
            shutil.rmtree(aspc.results_dir)

        if args.job_id:
            job_id = args.job_id
        else:
            job_id = "0"

        aspe = ASPExtractor(args.vendor, firmware_name, job_id=job_id)
        asp = aspe.extract_from_firmware(args.firmware_image, skip_extract=False)

        log.info("Saving extracted information")

        aspc = ASPCodec(asp)
        aspc.save()

        # make sure the entire policy directory hierarchy has the right permissions
        chown_parents(aspc.results_dir, output_uid, output_gid)

        # change the file and directory permissions to the specified user
        chown_recursive(aspc.results_dir, output_uid, output_gid)

        # make sure we can round-trip the data
        try:
            aspc.load()
        except ValueError:
            log.error("Unable to reload saved ASP. This is an internal error")
            return 1
    else:
        log.info("No extraction performed. %s already exists", firmware_name)

    return 0

if __name__ == "__main__":
    sys.exit(main())
