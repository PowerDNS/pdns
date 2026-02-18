import argparse
import subprocess
import sys
import os
import json
import time
import requests

# Pulp API/CLI credentials passed as ENV variables
PULP_API_URL = os.getenv("PULP_API_URL", "")
PULP_CI_USERNAME = os.getenv("PULP_CI_USERNAME", "")
PULP_CI_PASSWORD = os.getenv("PULP_CI_PASSWORD", "")
PULP_CMD_VENV = os.getenv("PULP_CMD_VENV", "")
PULP_API_AUTH = requests.auth.HTTPBasicAuth(PULP_CI_USERNAME, PULP_CI_PASSWORD)
PULP_API_HEADERS = {"Content-Type": "application/json"}


def run_pulp_cmd(cmd):
    """
    Executes pulp cli commands <pulp_cmd_prefix> + <cmd>. Retries up
    to 3 times in case of a temporary error
    """

    PULP_CMD = f'{PULP_CMD_VENV} --base-url {PULP_API_URL} --username {PULP_CI_USERNAME} --password {PULP_CI_PASSWORD}'

    max_attempts = 3
    attempts = 0
    while attempts < max_attempts:
        try:
            print(f"CMD: pulp {cmd}")
            res = subprocess.run(
                f"{PULP_CMD} {cmd}",
                shell = True,
                capture_output = True,
                check = True,
                text = True,
                timeout = 1800
            )
            return res.stdout
        except subprocess.CalledProcessError as e:
            attempts += 1
            if attempts == max_attempts:
                print(f"::error::Pulp command failed: {e.stderr.strip()}")
                sys.exit(1)
            print(f"::error::Pulp command failed: {e.stderr.strip()}. Retrying...")
            time.sleep(5)
        except subprocess.TimeoutExpired as e:
            print(f"::error::Pulp command timeout: {e.stderr.strip()}")
            sys.exit(1)


def get_pulp_output_attribute(output, attribute):
    try:
        data = json.loads(output)
        return data.get(attribute).strip()
    except json.JSONDecodeError as e:
        print(f"::error::Pulp output {output} not parseable: {e}")
        sys.exit(1)
    except KeyError:
        print(f"::error::Attribute {attribute} not found in {output}")
        sys.exit(1)


def get_pulp_repository_href(repo_name, repo_type):
    cmd = f"{repo_type} repository show --name {repo_name}"
    repository = run_pulp_cmd(cmd)
    repository_href = get_pulp_output_attribute(repository, "pulp_href")
    return repository_href


def create_deb_release_content(content_type, payload_json):
    url = PULP_API_URL + f"/pulp/api/v3/content/deb/{content_type}/"

    try:
        res = requests.post(
            url, auth=PULP_API_AUTH, headers=PULP_API_HEADERS, json=payload_json
        )
        res.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(f"::error::Error creating {content_type}: {e.response.text}")
        sys.exit(1)

    return res.json()


def get_deb_release_content_href(content_type, params_json):
    url = PULP_API_URL + f"/pulp/api/v3/content/deb/{content_type}/"

    try:
        res = requests.get(
            url, auth=PULP_API_AUTH, headers=PULP_API_HEADERS, params=params_json
        )
        res.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(f"::error::Error fetching {content_type}: {e.response.text}")
        sys.exit(1)

    if res.json().get('count') > 0:
        # return first result only
        return res.json().get('results')[0]['pulp_href']
    else:
        return False


def pulp_upload_file_packages_by_folder(repo_name, source, destination_path):
    """
    Uploads files in a repo of type file in 2 steps: first uploads
    the artifact whithout a type and the creates file object on a
    specific path
    """

    content_hrefs = []

    for root, dirs, files in os.walk(source):
        for file in files:
            full_path = os.path.join(root, file)
            # First upload file as an artifact
            cmd = f"file content upload --file {full_path} --relative-path {destination_path}/{file} --chunk-size 500MB"
            content = run_pulp_cmd(cmd)
            content_sha256 = get_pulp_output_attribute(content, "sha256")
            content_hrefs.append({"sha256": content_sha256, "relative_path": f"{destination_path}/{file}"})

    if content_hrefs:
        cmd = f"file repository content modify --repository {repo_name} --add-content '{json.dumps(content_hrefs)}'"
        run_pulp_cmd(cmd)
    else:
        print(
            f"::error::No File content HREF available for adding to repository {repo_name}."
        )
        sys.exit(1)


def pulp_create_publication(repo_name, repo_type):
    extra_args = " --checksum-type sha256" if repo_type == "rpm" else ""
    cmd = f"{repo_type} publication create --repository {repo_name}{extra_args}"
    run_pulp_cmd(cmd)


def pulp_upload_rpm_packages_by_folder(repo_name, source):
    for root, dirs, files in os.walk(source):
        for file in files:
            if file.endswith(".rpm"):
                full_path = os.path.join(root, file)
                # Set chunk size to 500MB to avoid creating an "upload" instead of a file. Required for signing RPMs.
                cmd = f"rpm content -t package upload --file {full_path} --repository {repo_name} --no-publish --chunk-size 500MB"
                run_pulp_cmd(cmd)


def is_pulp_task_completed(task_href):
    """
    This function waits <max_wait_time> for a task in Pulp to be completed
    and returns True. Otherwhise returns False
    """

    elapsed_time = 0
    check_interval = 5
    max_wait_time = 1200

    while elapsed_time < max_wait_time:
        cmd = f"task show --href {task_href}"
        task = run_pulp_cmd(cmd)
        task_state = get_pulp_output_attribute(task, "state")

        if task_state == "completed":
            return True

        time.sleep(check_interval)
        elapsed_time += check_interval

    return False


def pulp_upload_deb_packages_by_folder(repo_name, distribution_name, source):
    """
    This function uploads .deb packages to a Pulp deb repository. Done in 2 steps: first, it
    uploads the content without a repository associated and creating also the object associating the
    package to a release (release_component + release_architecture + package_release_component) that
    references a APT distribution i.e. noble-auth-50), and then adds all objects
    to the repository in batch mode to avoid blocking the resource in case of simultaneous uploads
    """

    packages = []
    release_components = []
    release_architectures = []
    package_release_components = []

    for root, dirs, files in os.walk(source):
        for file in files:
            if file.endswith(".deb"):
                full_path = os.path.join(root, file)
                cmd = f"deb content upload --file {full_path} --chunk-size 500MB"

                content = run_pulp_cmd(cmd)
                content_href = get_pulp_output_attribute(content, "pulp_href")
                content_architecture = get_pulp_output_attribute(content, "architecture")

                # Check is a new release component needs to be created
                rc_data = {
                    "component": "main",
                    "distribution": distribution_name
                }

                rc_href = get_deb_release_content_href("release_components", rc_data)

                if not rc_href:
                    rc = create_deb_release_content("release_components", rc_data)
                    rc_href = rc.get("pulp_href")

                # Check is a new release architecture needs to be created
                ra_data = {
                    "architecture": content_architecture,
                    "distribution": distribution_name
                }

                ra_href = get_deb_release_content_href("release_architectures", ra_data)

                if not ra_href:
                    ra = create_deb_release_content("release_architectures", ra_data)
                    ra_href = ra.get("pulp_href")

                # Check is a new package release component needs to be created
                prc_data = {
                    "package": content_href,
                    "release_component": rc_href
                }

                prc_href = get_deb_release_content_href("package_release_components", prc_data)

                if not prc_href:
                    prc = create_deb_release_content("package_release_components", prc_data)
                    prc_href = prc.get("pulp_href")

                packages.append(content_href)
                release_components.append(rc_href)
                release_architectures.append(ra_href)
                package_release_components.append(prc_href)

    # Add all upload packages to the repository
    repository_href = get_pulp_repository_href(repo_name, "deb")
    modify_repository_url = PULP_API_URL + repository_href + "modify/"

    repository_modify_payload = {
        "add_content_units": packages,
        "add_release_components": release_components,
        "add_release_architectures": release_architectures,
        "add_package_release_components": package_release_components
    }

    try:
        res = requests.post(
            modify_repository_url, auth=PULP_API_AUTH, headers=PULP_API_HEADERS, json=repository_modify_payload
        )
        res.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(f"::error::Error updating DEB repository in Pulp: {e.response.text}")
        sys.exit(1)

    task_href = res.json().get('task')
    if not is_pulp_task_completed(task_href):
        print(
            f"::error::Error updating DEB repository in Pulp. Task {task_href} timeout"
        )
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Pulp CLI wrapper")
    parser.add_argument(
        "--command",
        required=True,
        choices=["upload-packages", "create-publication"],
        help="Operation to perform [upload-packages|create-publication]",
    )
    parser.add_argument(
        "--repo_type",
        required=True,
        choices=["rpm", "deb", "file"],
        help="Type of the repository [rpm|deb|file]",
    )
    parser.add_argument("--repo_name", required=True, help="Name of the repository.")
    parser.add_argument(
        "--distribution_name",
        required=False,
        help="Name of the distribution in Pulp. Only needed for upload-packages + repo_type deb",
    )
    parser.add_argument(
        "--source",
        required=False,
        help="Absolute path where the packages can be found. Mandatory for upload-packages",
    )
    parser.add_argument(
        "--destination_path",
        required=False,
        help="Path inside the Pulp distribution where the file will be uploaded. Only needed for upload-packages + repo_type file",
    )

    args = parser.parse_args()

    if args.command == "upload-packages" and not args.source:
        parser.error("--source is mandatory for upload-packages")

    match (args.command, args.repo_type):
        case ("upload-packages", "rpm"):
            pulp_upload_rpm_packages_by_folder(args.repo_name, args.source)
        case ("upload-packages", "deb"):
            if not args.distribution_name:
                parser.error(
                    "--distribution_name is mandatory for upload-packages + repo_type deb"
                )
            pulp_upload_deb_packages_by_folder(
                args.repo_name, args.distribution_name, args.source
            )
        case ("upload-packages", "deb"):
            pulp_upload_deb_packages_by_folder(args.repo_name, args.source )
        case ("upload-packages", "file"):
            if not args.destination_path:
                parser.error(
                    "--destination_path is mandatory for upload-packages + repo_type file"
                )
            pulp_upload_file_packages_by_folder(
                args.repo_name, args.source, args.destination_path
            )
        case ("create-publication", repo_type):
            pulp_create_publication(args.repo_name, repo_type)
        case _:
            print(f"::error::Wrong arg values: mode={args.mode}, type={args.type}")
            sys.exit(1)


if __name__ == "__main__":
    main()
