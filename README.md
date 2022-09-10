# RE-Tool-Usability-Artifacts
This is a repo containing the environment, data, and analysis code to reproduce the results from the paper. This repo includes four files:

Fulldf.csv -- Our raw data set produced from the qualitative coding process of the plugins. This file must be placed in the same directory as the .Rmd file when running the markdown application.

FinalData.csv -- Our final data in csv format after all transformations and post processing have been applied.

RE Tool Usability Artifact.Rmd -- The R markdown file containing the code for posprocessing our raw data set, producing the visualizations used in the paper, and running the statistical tests reported in the results. This file is broken into multiple code blocks that should be independently executed as per the comments in the file. The best way to run this file is in a RStudio session.

RE_Tool_Usability.yaml -- The anaconda environment file to download RStudio and the necessary packages to run the R markdwon file. Installation instructions for the environment are below:

The environment for running the R markdown file is an Anaconda environment. To install and run the code please perform the following instructions:

1. Install Anaconda: Please visit the Anaconda documentation site to download the latest version of Anaconda. For simplicity I recomend installing the Anaconda Navigator as well. https://docs.anaconda.com/anaconda/install/

2. Install the RE Tool Usability environment: Once Anaconda is installed, and can be called from the console/terminal, it can be used to install the standard Python and R environment and tools. Download the environment file (it should be saved to your computer as RE_Tool_Usability.yaml). Once downloaded, you can execute the following command from the directory containing that file, in order to install all of the libraries required (this may take a few minutes).

  conda env create -f RE_Tool_Usability.yaml

  Alternatively, from the Anaconda Navigator window you can select the "Environments" tab on the left sidebar directly underneath "Home." From here you can see a list of  already installed environments. Bellow the list of installed environments you can click "Import" and then select the RE_Tool_Usability.yaml file to install the   environment.

3. Using the Environment: Once the environment has been created, you no longer need the downloaded yaml file. In order to use the environment, you can execute the      following command from the console/terminal:

  conda activate RE_Tool_Usability

  If using Anaconda Navigator, from the "Environments" tab click on the RE_Tool_Usability environment to load the necessary packages.

4. Running RStudio: Once the environment is active, you can launch R studio from the command line using the following command:

  rsudio

  If using the Anaconda Navigator, return to the "Home" tab to see a list of applications and click on the launch button under RStudio
