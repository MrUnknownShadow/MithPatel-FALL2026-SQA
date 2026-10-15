# MithPatel-FALL2026-SQA

**Team name:** MithPatel

| Member | Email |
|---|---|
| Mith Patel | mdp0068@auburn.edu |

COMP 5710/6710 Software Quality Assurance, Fall 2026 - SQA project on SLI-KUBE (`slikube.zip`).

| Activity | Where |
|---|---|
| Fuzzing 10 methods | [`fuzz.py`](fuzz.py), sample output in [`evidence/`](evidence/) |
| Forensics in 10 methods | [`forensics.py`](forensics.py), calls in `parser.py` / `scanner.py` |
| Continuous integration | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |
| Report and lessons learned | [`SQA-REPO.md`](SQA-REPO.md) |

```bash
pip install -r requirements-ci.txt
python fuzz.py --iterations 300          # writes fuzz_output/fuzz_report.{md,json}
python -m unittest TEST_PARSING          # writes forensics.log
python forensics.py --verify             # checks the log's hash chain
```

---

# Original project README (SLI-KUBE)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 

[![forthebadge made-with-python](http://ForTheBadge.com/images/badges/made-with-python.svg)](https://www.python.org/)

[![Actions Status](https://github.com/paser-group/KubeSec/workflows/Build%20KubeTaint/badge.svg)](https://github.com/Build%20TaintPupp/actions)


# Taintube: Taint Tracking for Security Analysis of Kubernetes Manifests 

## Development Environment
We use Conda to manage the virtual environment for KubeSec. To see the content of the environment, see [environment.yml](./environment.yml).

To use the environment, use the following commands.

```bash
# Create
conda env create -f environment.yml

# Activate
conda activate KUBESEC

# Deactivate
conda deactivate

# Export (if you modify the environment)
conda env export --from-history > environment.yml
```

## Running the tool

The tool is available as a Docker image: https://hub.docker.com/repository/docker/akondrahman/sli-kube 

### Instruction to run the tool from Docker Hub:

- docker rm $(docker ps -a -f status=exited -f status=created -q)
- docker rmi -f $(docker images -a -q)
- docker pull akondrahman/sli-kube
- docker images -a
- docker run --rm -it akondrahman/sli-kube bash
- cd SLI-KUBE-WORK/KubeSec-master/
- python3 main.py

### Build and run locally
You can also build the docker container locally.

After running the tool, you will find a CSV file called 'slikube_results.csv' in the scanned directory.

```bash
# Build the image
docker build -t slikube .

# Run the container 
# Replace '/Users/phu/Desktop/tf-open-source/aws-eks-base' with your local path
docker run --rm -v /Users/phu/Desktop/tf-open-source/aws-eks-base:/iac --name slikube slikube /iac
```

## Collaborators 

Akond Rahman (Lead), Rahul Pandita, and Shazibul Islam Shamim 


