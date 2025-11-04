#!/bin/zsh

# -x Print out all executed commands to the terminal.
# set -x
# -e  Exit immediately if a command exits with a non-zero status.
set -e

repository_name=trust-registry-rs
container_name=trust-registry-rs
login=false
update_configs=false
prod=false

# commit_sha must match version

# docker-http-server
commit_sha=docker-http-server
version=v0.1.0
release_frozen=true

version_suffix=-beta
version_suffix=
push_to_ecr=false

# pick the right platform
platforms="linux/amd64,linux/arm64/v8"
platforms="linux/arm64/v8"

default_platform=${platforms}
default_platform=linux/amd64
default_platform=linux/arm64
default_platform=linux/arm64/v8

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"
case $key in
    --name)
    container_name="$2"
    shift # past argument
    shift # past value
    ;;
    --login)
    login="true"
    shift # past argument
    # shift # past value
    ;;
    --update-configs)
    update_configs="true"
    shift # past argument
    # shift # past value
    ;;
    --prod)
    prod="true"
    shift # past argument
    # shift # past value
    ;;
    --version)
    version="$2"
    shift # past argument
    shift # past value
    ;;
    --commit-sha)
    commit_sha="$2"
    shift # past argument
    shift # past value
    ;;
    --push-to-ecr)
    push_to_ecr="true"
    shift # past argument
    # shift # past value
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

if [[ -z ${version} ]]
then
    echo "Version not specified"
    exit 1
fi

if [[ "${login}" = "true" ]]
then
    if [[ "${prod}" = "true" ]]
    then
        # log in into 905418212711/affinidi-elements-prod-affinidi-messaging
        # expanded version of: a-tla --tla msg
        . aws-this-prod.sh --tla msg --aws-role-name Admin
    else
        # log in into 471112687035/affinidi-elements-dev-affinidi-messaging
        # expanded version of: a-tla --tla msg
        . aws-this-dev.sh --tla msg
    fi
fi

version=${version}${version_suffix}

# AWS_ACCOUNT_ID, AWS_REGION and AWS_ACCOUNT_ID shall be exposed by a-tla
ecr_tag=${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${repository_name}:${version}
if [[ "${login}" = "true" ]]
then
    # login into AWS
    aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com
fi

# build the image

echo "Creating/using buildx env..."
docker buildx create --name ${repository_name} --use  >/dev/null 2>&1 || docker buildx use ${repository_name}

# rm -Rf trust-registry-rs || echo "trust-registry-rs not found, nothing to do"
# git clone --depth 1 --branch ${commit_sha} https://github.com/affinidi/trust-registry-rs.git
# cd ./trust-registry-rs

echo "Building the image..."
export DOCKER_GITHUB_TOKEN=${AFFINIDI_GITHUB_TOKEN}
docker buildx build \
    --platform ${platforms} \
    --pull \
    --load \
    --tag ${repository_name} \
    -f http-server/Dockerfile \
    .

# cd ..

echo "Tagging the source image..."
docker tag ${repository_name} ${repository_name}:${version}

if [[ "${login}" = "true" ]]
then
    echo "Tagging the target image..."
    docker tag ${repository_name}:${version} ${ecr_tag}
    if [[ "${push_to_ecr}" = "true" ]]
    then
        echo "Pushing the image to ECR..."
        docker push ${ecr_tag}
    fi
fi
