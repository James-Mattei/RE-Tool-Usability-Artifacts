# RE-Tool-Usability-Artifacts
This is a repo containing the environment, data, and analysis code to reproduce the results from the paper. This repo includes four files:

Fulldf.csv -- Our raw data set produced from the manual qualitative coding process of the plugins. This file is the aggregation of the qualitative coding that we performed across all the different tools. This file was not generated through any statistical techniques and represents the starting point for our data. The content of this file was entirely produced by the two qualitative coders as described in section 4.3 of the paper. This file must be placed in the same directory as the .Rmd file when running the markdown application.

FinalData.csv -- Our final data in csv format after all transformations and post processing have been applied.

RETools.R -- The R file containing the code for posprocessing our raw data set, producing the visualizations used in the paper, and running the statistical tests reported in the results. This file is loaded into the docker image along with Fulldf.csv. The best way to run this file is to pull the docker image and then run the application.


To install the docker image run the following command:

docker pull jam580/retools

You can confirm the image was properly downloaded by running:

docker images

Our analysis produces three figures (G1vInput.png, G1vOutContent.png, G1vOutMethod.png) that are used to create figures 2, 4, and 5 in the paper. The figures produced by the script were modified by hand to produce the final figures in the paper. Only the bars representing data that was used in the Chi-Squared tests were included, and certain bars were renamed to be more clear. For example in the G1vInput.png figure, the bars for "User defined input" was renamed to become "Scripts / Strings" in Figure 2. Certain bars were combined in the final figure to represent how the data was grouped for the Chi-squared tests. For example in the G1vOutContent.png figure, the "New patched code" and "Selected area O" bars were combined to form the "Code body" bar in Figure 4.

In order to see these figures you must mount a directory to the docker image. The figures are saved inside the docker image at the directory: /home/results 

If you are running from your home directory, the following sequence of commands will correctly set up a recieving folder for the results:

mkdir ~/results

docker run -v ~/results:/home/results jam580/retools

The r script will execute and the relevant outputs will be shown with a numbered delineation at the start of the line. The figures will be saved as .png files in the mounted folder (/results) on your local machine.

When running the script there will repeatedly be the following line in the output: 

`summarise()` has grouped output by 'X'. You can override using the
`.groups` argument.

This is a default prompt stating the summarise command has used one of the variables (X = G1, Static, Dynamic) to organize the output. This default parameter is the intended result and does not have any negative impact on our analysis.
