## This is a condensed version of the R markdown document used for our data analysis and processing. The first several code blocks load relevant
## libraries, import the raw data produced from qualitative coding (Fulldf.csv), and perform some of the preprocessing discussed in Section 4.3.
## If working from a new instalation of R, all library packages must be installed and the working directory must be set to the folder containing 
## the raw qualitative coding data file. The final form of the data is saved as "FinalData.csv."

library(lmtest)
library(ggplot2)
library(dplyr)
library(reshape)
library(reshape2)
library(tidyverse)
library(viridis)
library(forcats)


#Load raw data
data = read.csv(file ='Fulldf.csv', check.names = FALSE)
data$CodeVis = data$`Code Coverage / Vis.`
data = subset(data, select = -`Code Coverage / Vis.`)
summary(data$Framework)

## Setup filtering constants used for subselection
colfact = c("Overview", "Subcomponent", "Experimentation", 
            "Symbolic Execution", "CodeVis", "Modifying Non-Lang", "Modifying Lang", "Heuristic Scan/ PM",
            "Instruction Slicing", "Diff", "Inter framework transfer", "Decompiler", "Disassembler", "Fuzzing", 
            "Debugger", "Hooking/Patching","Kernel Symbol", "Devirtualize Calls", "Emulator", "Binary file I", 
            "Assembly file I", "Selected area I", "Operation mode", "Memory Dump", "Disassembly info I", "Decompiler info I",
            "Standard Input", "Database commands", "Debugger info I", "User defined input", "Trace info",
            "Binary file O", "Assembly file O", "Class information", "New patched code", "Cross references",
            "Function signatures", "String Matching", "Selected area O", "Variable information", "Standard output",
            "Debugger info O", "Emulator info", "Decompiler info O", "User modifications", "Binary data", "Decompiled CV",
            "Assembly CV", "Console log", "GUI Window", "Table", "Graph vis", "Image", "Highlighted segments",
            "Launches client plugin", "File creation / modification", "command line", "G3", "G4", "G5")
data[colfact] = lapply(data[colfact], function(x) as.numeric(as.character(x)))

frames = c("Binary", "Ghidra", "IDA", "RADARE2", "STANDALONE")

static = c("Symbolic Execution", "CodeVis", "Modifying Non-Lang", "Modifying Lang", "Heuristic Scan/ PM", "Instruction Slicing", "Diff", "Inter framework transfer", "Decompiler", "Disassembler")

## Group together both Modifying analysis conventions

dynamic = c("Fuzzing", "Debugger", "Hooking/Patching","Kernel Symbol", "Devirtualize Calls", "Emulator")

##

G1 = c("Overview", "Subcomponent", "Experimentation")

input = c("Binary file I", "Assembly file I", "Selected area I", "Operation mode", "Memory Dump", "Disassembly info I", "Decompiler info I","Standard Input", "Database commands", "Debugger info I", "User defined input", "Trace info")

binonly = c("Selected area I", "Operation mode", "Memory Dump", "Disassembly info I", "Decompiler info I","Standard Input", "Database commands", "Debugger info I", "User defined input", "Trace info")
##Group together binary file / assembly file input -->Input file
##Group togetehr Disassembly / Decompiler / Debugger info --> Tool info
##Group Operation mode / User defined input --> User specifications
##Group Memory Dump / Trace information / selected area --> State information
##Group Standard Input / Database commands --> User operation / Meta interaction
##Rename standard Input



outC = c("Binary file O", "Assembly file O", "Class information", "New patched code", "Cross references", "Function signatures", "String Matching", "Selected area O", "Variable information", "Standard output", "Debugger info O", "Emulator info", "Decompiler info O", "User modifications", "Binary data")

##Group together binary file / assembly file /  --> File creation
##Group together Debugger / Emulator / Decompiler information --> Tool info
##Group together Class information / function signatures / variable information / Cross references /  selected area / New patched code--> State information
##Group together String matching / Binary data --> Descriptive
##Group together Standard output / user modifications --> Meta info

outM = c("Decompiled CV", "Assembly CV", "Console log", "GUI Window", "Table", "Graph vis", "Image", "Highlighted segments", "Launches client plugin", "File creation / modification", "command line")

##Group together Decompiled, Assembly, Highlighted segments --> CodeView
##Group together Command line / Console log / Table --> text
##Group together Graph vis and Image GUI Window -> visualization

Int = c("G3", "G4", "G5")

Gs= c("G1", "G2", "G3", "G4", "G5")

totest = c("G1frame", "Funcframe", "castframe")


#Change input file coding to plugins that ONLY take a file as input
infile = data[data$`Binary file I`==1,]
in2 = data[data$`Assembly file I`==1,]
infile = rbind(infile, in2)
for( ty in binonly )
{
  infile = infile[infile[[ty]]==0,]
}

temp = anti_join(data, infile)

temp$`Binary file I`=0
temp$`Assembly file I`=0
data = rbind(temp,infile)


## Adding additional variables. Both is a categorical variable stating 
## if the plugin has functionality that is only static (0), dynamic (1), or both (2) 
## Code for creating the G2 classification outlined in section 4.3
## Code for creating the G1 classification outlined in section 4.3
logdf = data

logdf$staticdf = 0
logdf$dynamicdf = 0

##Switch to static, dynamic, both

##Allows us to say if only one of the func types is true, what the influence on G3-5 are
for(functy in static)
{
  logdf[logdf[[functy]]=="1",]$staticdf = 1
}

for(functy in dynamic)
{
  logdf[logdf[[functy]]=="1",]$dynamicdf = 1
}

logdf$staticdf = as.factor(logdf$staticdf)
logdf$dynamicdf = as.factor(logdf$dynamicdf)

logdf$both = 0


logdf[which(logdf$staticdf==1 & logdf$dynamicdf==1),]$both = 2
logdf[which(logdf$staticdf==0 & logdf$dynamicdf==1),]$both = 1

logdf$both=as.factor(logdf$both)

#Create the G2 variable for inline presentation of input and outputs
logdf$G2 = 0
logdf$G2[logdf$`Selected area I`==1] = 1
logdf$G2[logdf$`Selected area O`==1] = 1
logdf$G2[logdf$`New patched code`==1] = 1
logdf$G2[logdf$`Decompiled CV`==1] = 1
logdf$G2[logdf$`Assembly CV`==1] = 1
logdf$G2[logdf$`Highlighted segments`==1] = 1

#Create the G1 variable to indicate if a plugin is used to support transition between neighboring RE phases
logdf$G1 = 0

ovsub = logdf[logdf$Overview==1,]
ovsub= ovsub[ovsub$Subcomponent==1,]

subex = logdf[logdf$Subcomponent==1,]
subex = subex[subex$Experimentation==1,]

for (plugin in ovsub$Plugin) {
  logdf$G1[logdf$Plugin==plugin] = 1
}

for (plugin in subex$Plugin) {
  logdf$G1[logdf$Plugin==plugin] = 1
}

#write.csv(logdf,"FinalData.csv", row.names = FALSE)


## The following code blocks that generate the dataframes for the chi squared tests are also used to create the dataframes for some of the visualizations in the paper.
## The dataframes aggregating Analysis phase results (G1) are saved as "G1frame" The dataframe for plugin types are saved as "castframe". The dataframe for Functionality type are saved as "Funcframe"

## The Chi Squared tests compare input, output content, and output method against the other variables of our data set. The code blocks are grouped such
## that the relevant blocks to produce the results for each tests are together. Each grouping has a start and end deliniation (****) to make it more
## clear which tests are being run.


##*********** Relevant blocks for Input Chi Squared tests *********** 

#Generate Input type dataframes for Chi Squared tests
##************** Creating G1 type dataframe ********
#OVERVIEW
Odf = data[data$Overview=="1",]

Stat_ODF = Odf[,input]

Stat_ODF$G1 = "Overview"

mODF = melt(Stat_ODF, id.vars = "G1")

mODF$value = as.numeric(mODF$value)
#Final df
Ofinal =summarise(group_by(mODF,G1,variable), count = sum(value))


#EXPERIMENTATION
Edf = data[data$Experimentation=="1",]

Stat_EDF = Edf[,input]

Stat_EDF$G1 = "Experimentation"

mEDF = melt(Stat_EDF, id.vars = "G1")

mEDF$value = as.numeric(mEDF$value)
#Final df
Efinal =summarise(group_by(mEDF,G1,variable), count = sum(value))


#Subcomponent
Sdf = data[data$Subcomponent=="1",]

Stat_SDF = Sdf[,input]

Stat_SDF$G1 = "Subcomponent"

mSDF = melt(Stat_SDF, id.vars = "G1")

mSDF$value = as.numeric(mSDF$value)
#Final df
Sfinal =summarise(group_by(mSDF,G1,variable), count = sum(value))

bound = rbind(Efinal,Sfinal,Ofinal)
G1frame = cast(bound, G1~variable, "sum")
rownames(G1frame) = G1frame$G1
##DOUBLE CHECK YOU ARE SLICING THE RIGHT THING!!!
G1frame = G1frame[,2:13]


##******** CREATING functionality type dataframe ************
Statdf = data[,c(static, input)]
cols = c("Static", "variable", "count")
StatInput = data.frame(matrix(nrow=0, ncol = 3))
colnames(StatInput) = cols

first = 0
for(functy in static)
{
  fun1 = Statdf[Statdf[[functy]]=="1",]
  Stat_fun1 = fun1[,input]
  if(nrow(Stat_fun1)==0)
  {
    next()
  }
  else
  {
    Stat_fun1$Static = functy
    mFDF = melt(Stat_fun1, id.vars = "Static")
    mFDF$value = as.numeric(as.character(mFDF$value))
    mfin = summarise(group_by(mFDF,Static,variable), count = sum(value))
    if(first==0)
    {
      StatInput = mfin
      first =1
    }
    else
    {
      StatInput = rbind(StatInput, mfin)
    }
  }
}

Stathalf = cast(StatInput, Static~variable, "sum")
stattemp = data.frame(matrix(nrow = 0, ncol = 12))
stattemp =rbind(stattemp, colSums(Stathalf[,2:13]) ) 
colnames(stattemp) = input
rownames(stattemp) = "Static"


Dyndf = data[,c(dynamic, input)]
cols = c("Static", "variable", "count")
DynInput = data.frame(matrix(nrow=0, ncol = 3))
colnames(DynInput) = cols

first = 0
for(functy in dynamic)
{
  fun1 = Dyndf[Dyndf[[functy]]=="1",]
  Stat_fun1 = fun1[,input]
  if(nrow(Stat_fun1)==0)
  {
    next()
  }
  else
  {
    Stat_fun1$Dynamic = functy
    mFDF = melt(Stat_fun1, id.vars = "Dynamic")
    mFDF$value = as.numeric(mFDF$value)
    mfin = summarise(group_by(mFDF,Dynamic,variable), count = sum(value))
    if(first==0)
    {
      DynInput = mfin
      first =1
    }
    else
    {
      DynInput = rbind(DynInput, mfin)
    }
  }
}

Dynhalf = cast(DynInput, Dynamic~variable, "sum")
dyntemp = data.frame(matrix(nrow = 0, ncol = 12))
dyntemp =rbind(dyntemp, colSums(Dynhalf[,2:13]) ) 
colnames(dyntemp) = input
rownames(dyntemp) = "Dynamic"

Funcframe = rbind(stattemp, dyntemp)

##**************** Creating Framework dataframe *********************

#OVERVIEW
Odf = data[,c("Framework","Client Plugin", input)]
Nonclient = Odf[Odf$`Client Plugin`==FALSE,]
clients = Odf[Odf$`Client Plugin`==TRUE,]

##clients
clients = clients[,3:14]
clients$Framework = "Client Plugin"
mclient = melt(clients, id.vars = "Framework")
mclient$value=as.numeric(as.character(mclient$value))
mclientsum = summarise(group_by(mclient,Framework,variable), count = sum(value))
clientcast = cast(mclientsum, Framework~variable, "sum")

##Nonclients
Nostand = Nonclient[Nonclient$Framework!="STANDALONE",]
Nostand = Nostand[,3:14]
Nostand$Framework = "Integrated Plugins"
mNclient = melt(Nostand, id.vars = "Framework")
mNclient$value=as.numeric(as.character(mNclient$value))
mNclisum = summarise(group_by(mNclient,Framework,variable),count = sum(value))
Nclicast = cast(mNclisum, Framework~variable, "sum")

##Standalones

stand = Nonclient[Nonclient$Framework=="STANDALONE",]
stand = stand[,3:14]
stand$Framework = "Standalone"
mstand = melt(stand, id.vars = "Framework")
mstand$value=as.numeric(as.character(mstand$value))
mstandsum = summarise(group_by(mstand, Framework, variable), count = sum(value))
standcast = cast(mstandsum,Framework~variable, "sum")

castframe = rbind(clientcast, Nclicast, standcast)
rownames(castframe) = castframe$Framework
##DOUBLE CHECK YOU ARE SLICING THE RIGHT THING
castframe = castframe[,2:13]


##Group inputs together
group_input = function(castdf)
{
  castdf$Infile = castdf$`Binary file I` + castdf$`Assembly file I`
  castdf = subset(castdf, select = -c(`Binary file I`,`Assembly file I` ))
  
  castdf$Config = castdf$`Operation mode` + castdf$`User defined input`
  castdf = subset(castdf, select = -c(`Operation mode`,`User defined input` ))
  
  castdf$StateInfo = castdf$`Memory Dump` + castdf$ `Trace info` + castdf$`Debugger info I`
  castdf = subset(castdf, select = -c(`Memory Dump`,`Trace info`, `Debugger info I`))
  
  castdf$SA =  castdf$`Selected area I`
  
  castdf$MetaInfo = castdf$`Standard Input` + castdf$`Database commands` + castdf$`Disassembly info I`+ castdf$`Decompiler info I` 
  castdf = subset(castdf, select = -c(`Standard Input`,`Database commands`, `Selected area I` ))
  castdf = subset(castdf, select = -c(`Disassembly info I`,`Decompiler info I`))
  return(castdf)
}

G1frame = group_input(G1frame)
Funcframe = group_input(Funcframe)
castframe = group_input(castframe)


##Check output for which omnibus tests are significant to match final pvalues to comparisons
#Chi squared against INPUT TYPES


##First check if omnibus is significant
chisq = chisq.test(G1frame)

chisq$p.value
G1inP = chisq$p.value

if(G1inP<0.05)
{
  print("G1 omnibus test was significant!")
  #If val is sig move onto pairwise comps
  #f1 is Overview vs Subcomponent
  f1 = G1frame[2:3,]
  #f2 is Overview vs Experimentation
  f2 = G1frame[1:2,]
  #f3 is Subcomponent vs Experimentation
  f3 = G1frame[c(1,3),]
  
  
  f1p1 = subset(f1, select = c(Config, StateInfo))
  f1p2 = subset(f1, select = c(Config, SA))
  f1p3 = subset(f1, select = c(StateInfo, SA))
  
  
  f2p1 = subset(f2, select = c(Config, StateInfo))
  f2p2 = subset(f2, select = c(Config, SA))
  f2p3 = subset(f2, select = c(StateInfo, SA))
  
  f3p1 = subset(f3, select = c(Config, StateInfo))
  f3p2 = subset(f3, select = c(Config, SA))
  f3p3 = subset(f3, select = c(StateInfo, SA))
  
  cf1p1 = chisq.test(f1p1)
  cf1p2 = chisq.test(f1p2)
  cf1p3 = chisq.test(f1p3)
  cf2p1 = chisq.test(f2p1)
  cf2p2 = chisq.test(f2p2)
  cf2p3 = chisq.test(f2p3)
  cf3p1 = chisq.test(f3p1)
  cf3p2 = chisq.test(f3p2)
  cf3p3 = chisq.test(f3p3)
  
  pvals = list(G1inP, cf1p1$p.value, cf1p2$p.value, cf1p3$p.value,
               cf2p1$p.value, cf2p2$p.value, cf2p3$p.value,
               cf3p1$p.value, cf3p2$p.value, cf3p3$p.value)
  
  chis = list(chisq$statistic, cf1p1$statistic, cf1p2$statistic, cf1p3$statistic,
              cf2p1$statistic, cf2p2$statistic, cf2p3$statistic,
              cf3p1$statistic, cf3p2$statistic, cf3p3$statistic )
}else
{
  pvals = list(G1inP)
  chis = list(chisq$statistic)
}

##Do it again for Framework

chisq = chisq.test(castframe)

chisq$p.value
frameP = chisq$p.value

if(frameP<0.05)
{
  print("Framework omnibus was significant!")
  #If val is sig move onto pairwise comps
  #f1 is integrated vs Standalone
  f1 = castframe[2:3,]
  #f2 is Client vs Integrated
  f2 = castframe[1:2,]
  #f3 is Client vs Standalone
  f3 = castframe[c(1,3),]
  
  
  f1p1 = subset(f1, select = c(Config, StateInfo))
  f1p2 = subset(f1, select = c(Config, SA))
  f1p3 = subset(f1, select = c(StateInfo, SA))
  
  f2p1 = subset(f2, select = c(Config, StateInfo))
  f2p2 = subset(f2, select = c(Config, SA))
  f2p3 = subset(f2, select = c(StateInfo, SA))
  
  f3p1 = subset(f3, select = c(Config, StateInfo))
  f3p2 = subset(f3, select = c(Config, SA))
  f3p3 = subset(f3, select = c(StateInfo, SA))
  
  cf1p1 = chisq.test(f1p1)
  cf1p2 = chisq.test(f1p2)
  cf1p3 = chisq.test(f1p3)
  cf2p1 = chisq.test(f2p1)
  cf2p2 = chisq.test(f2p2)
  cf2p3 = chisq.test(f2p3)
  cf3p1 = chisq.test(f3p1)
  cf3p2 = chisq.test(f3p2)
  cf3p3 = chisq.test(f3p3)
  
  pvals = append(pvals, list(frameP, cf1p1$p.value, cf1p2$p.value, cf1p3$p.value,
                             cf2p1$p.value, cf2p2$p.value, cf2p3$p.value,
                             cf3p1$p.value, cf3p2$p.value, cf3p3$p.value))
  chis = append (chis, list(chisq$statistic, cf1p1$statistic, cf1p2$statistic, cf1p3$statistic,
                            cf2p1$statistic, cf2p2$statistic, cf2p3$statistic,
                            cf3p1$statistic, cf3p2$statistic, cf3p3$statistic ))
}else
{
  print("Appending: ")
  print(frameP)
  pvals = append(pvals, frameP)
  chis = append(chis, chisq$statistic)
}

##Now finaly for Static vs Dynamic

chisq = chisq.test(Funcframe)

chisq$p.value
funcP = chisq$p.value

if(funcP<0.05)
{
  #If val is sig move onto pairwise comps
  print("Functionality type omnibus is significant")
  f1 = Funcframe[1:2,]
  
  f1p1 = subset(f1, select = c(Config, StateInfo))
  f1p2 = subset(f1, select = c(Config, SA))
  f1p3 = subset(f1, select = c(StateInfo, SA))
  
  cf1p1 = chisq.test(f1p1)
  cf1p2 = chisq.test(f1p2)
  cf1p3 = chisq.test(f1p3)
  
  
  pvals = append(pvals, list(funcP, cf1p1$p.value, cf1p2$p.value, cf1p3$p.value))
  chis = append (chis, list(chisq$statistic, cf1p1$statistic, cf1p2$statistic, cf1p3$statistic))
}else
{
  print("Appending: ")
  print(funcP)
  pvals = append(pvals, funcP)
  chis = append(chis, chisq$statistic)
}

##Finally correct the pvalues!
print("Final input Chi Squared results")
print(p.adjust(pvals, method="BH", n = length(pvals)))


## Code to produce the bars used to create Figure 2 in Section 5 of the paper.
#Remove Binary file from input to see others more clearly
test = subset(bound,variable!="Binary file I")
test = subset(test, variable!="Disassembly info I")

test$G1 = ordered(test$G1, levels = c("Experimentation", "Subcomponent", "Overview"))

##Plotting with binary file removed
p1 = ggplot(test, aes(fill = G1,x =variable, y= count))+ geom_bar(stat = "identity")
p1 = p1 + theme(plot.margin = unit(c(1,1,1,1), "cm"),text=element_text(family="Arial",size=12),legend.position="bottom",panel.grid.major.y=element_blank(), panel.grid.major.x=element_line(colour="black"),panel.grid.minor=element_blank(),panel.background = element_rect(fill="white"),axis.text.y=element_text(colour = "black"),axis.text.x=element_text(colour = "black"),axis.ticks.y=element_blank(),axis.title.y=element_blank(),axis.title.x=element_blank())
p1 + coord_flip()+scale_fill_brewer(palette = "Set1")



#Uncomment bellow commands to view this figure with Binary file Input included

#bound$G1 = ordered(bound$G1, levels = c("Experimentation", "Subcomponent", "Overview"))
#p = ggplot(bound, aes(fill = G1,x =variable, y= count))+ geom_bar(stat = "identity")
#p = p + theme(plot.margin = unit(c(1,1,1,1), "cm"),text=element_text(family="Arial",size=12),legend.position="bottom",panel.grid.major.y=element_blank(), panel.grid.major.x=element_line(colour="black"),panel.grid.minor=element_blank(),panel.background = element_rect(fill="white"),axis.text.y=element_text(colour = "black"),axis.text.x=element_text(colour = "black"),axis.ticks.y=element_blank(),axis.title.y=element_blank(),axis.title.x=element_blank())
#p + coord_flip()

##***********End of Input Chi Squared tests *********** 


##*********** Relevant blocks for Output Content Chi Squared tests *********** 

#Generate Output Content type dataframes for Chi Squared tests
##************** Creating G1 type dataframe ********
#OVERVIEW
Odf = data[data$Overview=="1",]

Stat_ODF = Odf[,outC]

Stat_ODF$G1 = "Overview"

mODF = melt(Stat_ODF, id.vars = "G1")

mODF$value = as.numeric(mODF$value)
#Final df
Ofinal =summarise(group_by(mODF,G1,variable), count = sum(value))


#EXPERIMENTATION
Edf = data[data$Experimentation=="1",]

Stat_EDF = Edf[,outC]

Stat_EDF$G1 = "Experimentation"

mEDF = melt(Stat_EDF, id.vars = "G1")

mEDF$value = as.numeric(mEDF$value)
#Final df
Efinal =summarise(group_by(mEDF,G1,variable), count = sum(value))


#Subcomponent
Sdf = data[data$Subcomponent=="1",]

Stat_SDF = Sdf[,outC]

Stat_SDF$G1 = "Subcomponent"

mSDF = melt(Stat_SDF, id.vars = "G1")

mSDF$value = as.numeric(mSDF$value)
#Final df
Sfinal =summarise(group_by(mSDF,G1,variable), count = sum(value))

bound = rbind(Efinal,Sfinal,Ofinal)
G1frame = cast(bound, G1~variable, "sum")
rownames(G1frame) = G1frame$G1
##DOUBLE CHECK YOU ARE SLICING THE RIGHT THING!!!
G1frame = G1frame[,2:16]

##************** Creating Functionality type dataframe ********
Statdf = select(data, c(static, outC))
cols = c("Static", "variable", "count")
StatoutC = data.frame(matrix(nrow=0, ncol = 3))
colnames(StatoutC) = cols

first = 0
for(functy in static)
{
  fun1 = Statdf[Statdf[[functy]]=="1",]
  Stat_fun1 = fun1[,outC]
  if(nrow(Stat_fun1)==0)
  {
    next()
  }
  else
  {
    Stat_fun1$Static = functy
    mFDF = melt(Stat_fun1, id.vars = "Static")
    mFDF$value = as.numeric(mFDF$value)
    mfin = summarise(group_by(mFDF,Static,variable), count = sum(value))
    if(first==0)
    {
      StatoutC = mfin
      first =1
    }
    else
    {
      StatoutC = rbind(StatoutC, mfin)
    }
  }
}

Stathalf = cast(StatoutC, Static~variable, "sum")
stattemp = data.frame(matrix(nrow = 0, ncol = 12))
##DOUBLE CHECK YOU ARE SLICING RIGHT COLS!!!!!!!!!!!!!!!!!
stattemp =rbind(stattemp, colSums(Stathalf[,2:16]) ) 
colnames(stattemp) = outC
rownames(stattemp) = "Static"


Dyndf = data[,c(dynamic, outC)]
cols = c("Static", "variable", "count")
DynoutC = data.frame(matrix(nrow=0, ncol = 3))
colnames(DynoutC) = cols

first = 0
for(functy in dynamic)
{
  fun1 = Dyndf[Dyndf[[functy]]=="1",]
  Stat_fun1 = fun1[,outC]
  if(nrow(Stat_fun1)==0)
  {
    next()
  }
  else
  {
    Stat_fun1$Dynamic = functy
    mFDF = melt(Stat_fun1, id.vars = "Dynamic")
    mFDF$value = as.numeric(mFDF$value)
    mfin = summarise(group_by(mFDF,Dynamic,variable), count = sum(value))
    if(first==0)
    {
      DynoutC = mfin
      first =1
    }
    else
    {
      DynoutC = rbind(DynoutC, mfin)
    }
  }
}

Dynhalf = cast(DynoutC, Dynamic~variable, "sum")
dyntemp = data.frame(matrix(nrow = 0, ncol = 12))
##DOUBLE CHECK YOU ARE SLICING RIGHT COLS!!!!!!!!!!!!!!!!!
dyntemp =rbind(dyntemp, colSums(Dynhalf[,2:16]) ) 
colnames(dyntemp) = outC
rownames(dyntemp) = "Dynamic"

Funcframe = rbind(stattemp, dyntemp)


##************** Creating Framework type dataframe ********
Odf = data[,c("Framework","Client Plugin", outC)]
Nonclient = Odf[Odf$`Client Plugin`==FALSE,]
clients = Odf[Odf$`Client Plugin`==TRUE,]

##clients
##DOUBLE CHECK YOU ARE SLICING THE RIGHT COLS!!!!!
clients = clients[,3:17]
clients$Framework = "Client Plugin"
mclient = melt(clients, id.vars = "Framework")
mclient$value = as.numeric(mclient$value)
mclientsum = summarise(group_by(mclient,Framework,variable), count = sum(value))
clientcast = cast(mclientsum, Framework~variable, "sum")

##Nonclients
Nostand = Nonclient[Nonclient$Framework!="STANDALONE",]
##DOUBLE CHECK YOU ARE SLICING THE RIGHT COLS!!!!!
Nostand = Nostand[,3:17]
Nostand$Framework = "Integrated Plugins"
mNclient = melt(Nostand, id.vars = "Framework")
mNclient$value = as.numeric(mNclient$value)
mNclisum = summarise(group_by(mNclient,Framework,variable),count = sum(value))
Nclicast = cast(mNclisum, Framework~variable, "sum")

##Standalones

stand = Nonclient[Nonclient$Framework=="STANDALONE",]
##DOUBLE CHECK YOU ARE SLICING THE RIGHT COLS!!!!!
stand = stand[,3:17]
stand$Framework = "Standalone"
mstand = melt(stand, id.vars = "Framework")
mstand$value = as.numeric(mstand$value)
mstandsum = summarise(group_by(mstand, Framework, variable), count = sum(value))
standcast = cast(mstandsum,Framework~variable, "sum")

castframe = rbind(clientcast, Nclicast, standcast)
rownames(castframe) = castframe$Framework
castframe = castframe[,2:16]

##Check output for which omnibus tests are significant to match final pvalues to comparisons
##GROUP OUTC TOGETHER
group_outC = function(castdf)
{
  castdf$FileMod = castdf$`Binary file O` + castdf$`Assembly file O` 
  castdf = subset(castdf, select = -c(`Binary file O`,`Assembly file O`))
  
  castdf$ToolInfo = castdf$`Debugger info O` + castdf$`Emulator info` + castdf$`Decompiler info O`
  castdf = subset(castdf, select = -c(`Debugger info O`,`Emulator info`, `Decompiler info O`))
  
  castdf$StateInfo = castdf$`Class information` + castdf$`Function signatures` +castdf$`Variable information`  + castdf$`New patched code` + castdf$`Selected area O`
  castdf = subset(castdf, select = -c(`Class information`,`Function signatures`, `Variable information`, `New patched code`, `Selected area O`))
  
  castdf$Descriptive = castdf$`String Matching` + castdf$`Binary data` + castdf$`Cross references` 
  castdf = subset(castdf, select = -c(`String Matching`, `Binary data`, `Cross references`))
  
  castdf$MetaInfo = castdf$`Standard output`
  castdf = subset(castdf, select = -c(`Standard output`))
  
  castdf$Usermod = castdf$`User modifications`
  castdf = subset(castdf, select = -c(`User modifications`))
  
  return(castdf)
}

G1frame = group_outC(G1frame)
Funcframe = group_outC(Funcframe)
castframe = group_outC(castframe)

##CHISQ AGAINST OUTPUT CONTENT
##First check if omnibus is significant
chisq = chisq.test(G1frame)

chisq$p.value
G1inP = chisq$p.value

if(G1inP<0.05)
{
  print("G1 omnibus test was significant!")
  #If val is sig move onto pairwise comps
  
  #f1 is Overview vs Subcomponent
  f1 = G1frame[2:3,]
  #f2 is Overview vs Experimentation
  f2 = G1frame[1:2,]
  #f3 is Subcomponent vs Experimentation
  f3 = G1frame[c(1,3),]
  
  f1p1 = subset(f1, select = c(ToolInfo, Descriptive))
  f1p2 = subset(f1, select = c(ToolInfo, StateInfo))
  f1p3 = subset(f1, select = c(StateInfo, Descriptive))
  
  
  f2p1 = subset(f2, select = c(ToolInfo, Descriptive))
  f2p2 = subset(f2, select = c(ToolInfo, StateInfo))
  f2p3 = subset(f2, select = c(StateInfo, Descriptive))
  
  
  f3p1 = subset(f3, select = c(ToolInfo, Descriptive))
  f3p2 = subset(f3, select = c(ToolInfo, StateInfo))
  f3p3 = subset(f3, select = c(StateInfo, Descriptive))
  
  
  cf1p1 = chisq.test(f1p1)
  cf1p2 = chisq.test(f1p2)
  cf1p3 = chisq.test(f1p3)
  
  
  cf2p1 = chisq.test(f2p1)
  cf2p2 = chisq.test(f2p2)
  cf2p3 = chisq.test(f2p3)
  
  
  
  cf3p1 = chisq.test(f3p1)
  cf3p2 = chisq.test(f3p2)
  cf3p3 = chisq.test(f3p3)
  
  
  
  pvals = list(G1inP, cf1p1$p.value, cf1p2$p.value, cf1p3$p.value, 
               cf2p1$p.value, cf2p2$p.value, cf2p3$p.value, 
               cf3p1$p.value, cf3p2$p.value, cf3p3$p.value)
  chis = list(chisq$statistic, cf1p1$statistic, cf1p2$statistic, cf1p3$statistic,
              cf2p1$statistic, cf2p2$statistic, cf2p3$statistic,
              cf3p1$statistic, cf3p2$statistic, cf3p3$statistic )
}else
{
  print("OMG NOT SIG")
  pvals = list(G1inP)
  chis = list(chisq$statistic)
}

##Do it again for Framework

chisq = chisq.test(castframe)

chisq$p.value
frameP = chisq$p.value

if(frameP<0.05)
{
  print("Framework omnibus was significant!")
  #If val is sig move onto pairwise comps
  #f1 is integrated vs Standalone
  f1 = castframe[2:3,]
  #f2 is Client vs Integrated
  f2 = castframe[1:2,]
  #f3 is Client vs Standalone
  f3 = castframe[c(1,3),]
  
  
  f1p1 = subset(f1, select = c(ToolInfo, Descriptive))
  f1p2 = subset(f1, select = c(ToolInfo, StateInfo))
  f1p3 = subset(f1, select = c(StateInfo, Descriptive))
  
  
  f2p1 = subset(f2, select = c(ToolInfo, Descriptive))
  f2p2 = subset(f2, select = c(ToolInfo, StateInfo))
  f2p3 = subset(f2, select = c(StateInfo, Descriptive))
  
  
  f3p1 = subset(f3, select = c(ToolInfo, Descriptive))
  f3p2 = subset(f3, select = c(ToolInfo, StateInfo))
  f3p3 = subset(f3, select = c(StateInfo, Descriptive))
  
  
  cf1p1 = chisq.test(f1p1)
  cf1p2 = chisq.test(f1p2)
  cf1p3 = chisq.test(f1p3)
  
  
  cf2p1 = chisq.test(f2p1)
  cf2p2 = chisq.test(f2p2)
  cf2p3 = chisq.test(f2p3)
  
  
  
  cf3p1 = chisq.test(f3p1)
  cf3p2 = chisq.test(f3p2)
  cf3p3 = chisq.test(f3p3)
  
  
  
  temp = list(G1inP, cf1p1$p.value, cf1p2$p.value, cf1p3$p.value, 
              cf2p1$p.value, cf2p2$p.value, cf2p3$p.value, 
              cf3p1$p.value, cf3p2$p.value, cf3p3$p.value)
  pvals = append(pvals, temp)
  
  chis = append(chis, list(chisq$statistic, cf1p1$statistic, cf1p2$statistic, cf1p3$statistic,
                           cf2p1$statistic, cf2p2$statistic, cf2p3$statistic,
                           cf3p1$statistic, cf3p2$statistic, cf3p3$statistic ))
}else
{
  print("Appending: ")
  print(frameP)
  pvals = append(pvals, frameP)
  chis = append(chis, chisq$statistic)
}

##Now finaly for Static vs Dynamic

chisq = chisq.test(Funcframe)

chisq$p.value
funcP = chisq$p.value

if(funcP<0.05)
{
  #If val is sig move onto pairwise comps
  print("Functionality type omnibus is significant")
  f1 = Funcframe[1:2,]
  
  f1p1 = subset(f1, select = c(ToolInfo, Descriptive))
  f1p2 = subset(f1, select = c(ToolInfo, StateInfo))
  f1p3 = subset(f1, select = c(StateInfo, Descriptive))
  
  
  cf1p1 = chisq.test(f1p1)
  cf1p2 = chisq.test(f1p2)
  cf1p3 = chisq.test(f1p3)
  
  
  pvals = append(pvals, c( funcP, cf1p1$p.value, cf1p2$p.value, cf1p3$p.value))
  chis = append(chis, list(chisq$statistic, cf1p1$statistic, cf1p2$statistic, cf1p3$statistic))
}else
{
  print("Appending: ")
  print(funcP)
  pvals = append(pvals, funcP)
  chis = append(chis,chisq$statistic)
}

##Finally correct the pvalues!
print("Final Output Content Chi Squared results")
print(p.adjust(pvals, method="BH", n = length(pvals)))


## Code to produce the bars used to create Figure 3 in Section 5 of the paper.
bound$G1 = ordered(bound$G1, levels = c("Experimentation", "Subcomponent", "Overview"))

p = ggplot(bound, aes(fill = G1,x =variable, y= count))+ geom_bar(stat = "identity")
p = p + theme(plot.margin = unit(c(1,1,1,1), "cm"),text=element_text(family="Arial",size=12),legend.position="bottom",panel.grid.major.y=element_blank(), panel.grid.major.x=element_line(colour="black"),panel.grid.minor=element_blank(),panel.background = element_rect(fill="white"),axis.text.y=element_text(colour = "black"),axis.text.x=element_text(colour = "black"),axis.ticks.y=element_blank(),axis.title.y=element_blank(),axis.title.x=element_blank())
p + coord_flip()+scale_fill_brewer(palette = "Set1")

##*********** End of Output Content Chi Squared tests *********** 


##*********** Relevant blocks for Output Method Chi Squared tests *********** 

#Generate Output Method type dataframes for Chi Squared tests
##************** Creating G1 type dataframe ********
#OVERVIEW
Odf = data[data$Overview=="1",]

Stat_ODF = Odf[,outM]

Stat_ODF$G1 = "Overview"

mODF = melt(Stat_ODF, id.vars = "G1")

mODF$value = as.numeric(mODF$value)
#Final df
Ofinal =summarise(group_by(mODF,G1,variable), count = sum(value))


#EXPERIMENTATION
Edf = data[data$Experimentation=="1",]

Stat_EDF = Edf[,outM]

Stat_EDF$G1 = "Experimentation"

mEDF = melt(Stat_EDF, id.vars = "G1")

mEDF$value = as.numeric(mEDF$value)
#Final df
Efinal =summarise(group_by(mEDF,G1,variable), count = sum(value))


#Subcomponent
Sdf = data[data$Subcomponent=="1",]

Stat_SDF = Sdf[,outM]

Stat_SDF$G1 = "Subcomponent"

mSDF = melt(Stat_SDF, id.vars = "G1")

mSDF$value = as.numeric(mSDF$value)
#Final df
Sfinal =summarise(group_by(mSDF,G1,variable), count = sum(value))

bound = rbind(Efinal,Sfinal,Ofinal)

G1frame = cast(bound, G1~variable, "sum")
rownames(G1frame) = G1frame$G1
##DOUBLE CHECK YOU ARE SLICING THE RIGHT THING!!!
G1frame = G1frame[,2:12]

##************** Creating Functionaity type dataframe ********

Statdf = data[,c(static, outM)]
cols = c("Static", "variable", "count")
StatoutC = data.frame(matrix(nrow=0, ncol = 3))
colnames(StatoutC) = cols

first = 0
for(functy in static)
{
  fun1 = Statdf[Statdf[[functy]]=="1",]
  Stat_fun1 = fun1[,outM]
  if(nrow(Stat_fun1)==0)
  {
    next()
  }
  else
  {
    Stat_fun1$Static = functy
    mFDF = melt(Stat_fun1, id.vars = "Static")
    mFDF$value = as.numeric(mFDF$value)
    mfin = summarise(group_by(mFDF,Static,variable), count = sum(value))
    if(first==0)
    {
      StatoutC = mfin
      first =1
    }
    else
    {
      StatoutC = rbind(StatoutC, mfin)
    }
  }
}

Stathalf = cast(StatoutC, Static~variable, "sum")
stattemp = data.frame(matrix(nrow = 0, ncol = 12))
##DOUBLE CHECK YOU ARE SLICING RIGHT COLS!!!!!!!!!!!!!!!!!
stattemp =rbind(stattemp, colSums(Stathalf[,2:12]) ) 
colnames(stattemp) = outM
rownames(stattemp) = "Static"


Dyndf = data[,c(dynamic, outM)]
cols = c("Static", "variable", "count")
DynoutC = data.frame(matrix(nrow=0, ncol = 3))
colnames(DynoutC) = cols

first = 0
for(functy in dynamic)
{
  fun1 = Dyndf[Dyndf[[functy]]=="1",]
  Stat_fun1 = fun1[,outM]
  if(nrow(Stat_fun1)==0)
  {
    next()
  }
  else
  {
    Stat_fun1$Dynamic = functy
    mFDF = melt(Stat_fun1, id.vars = "Dynamic")
    mFDF$value = as.numeric(mFDF$value)
    mfin = summarise(group_by(mFDF,Dynamic,variable), count = sum(value))
    if(first==0)
    {
      DynoutC = mfin
      first =1
    }
    else
    {
      DynoutC = rbind(DynoutC, mfin)
    }
  }
}

Dynhalf = cast(DynoutC, Dynamic~variable, "sum")
dyntemp = data.frame(matrix(nrow = 0, ncol = 12))
##DOUBLE CHECK YOU ARE SLICING RIGHT COLS!!!!!!!!!!!!!!!!!
dyntemp =rbind(dyntemp, colSums(Dynhalf[,2:12]) ) 
colnames(dyntemp) = outM
rownames(dyntemp) = "Dynamic"

Funcframe = rbind(stattemp, dyntemp)

##************** Creating Framework type dataframe ********

Odf = data[,c("Framework","Client Plugin", outM)]
Nonclient = Odf[Odf$`Client Plugin`==FALSE,]
clients = Odf[Odf$`Client Plugin`==TRUE,]

##clients
##DOUBLE CHECK YOU ARE SLICING THE RIGHT COLS!!!!!
clients = clients[,3:13]
clients$Framework = "Client Plugin"
mclient = melt(clients, id.vars = "Framework")
mclientsum = summarise(group_by(mclient,Framework,variable), count = sum(value))
clientcast = cast(mclientsum, Framework~variable, "sum")

##Nonclients
Nostand = Nonclient[Nonclient$Framework!="STANDALONE",]
##DOUBLE CHECK YOU ARE SLICING THE RIGHT COLS!!!!!
Nostand = Nostand[,3:13]
Nostand$Framework = "Integrated Plugins"
mNclient = melt(Nostand, id.vars = "Framework")
mNclisum = summarise(group_by(mNclient,Framework,variable),count = sum(value))
Nclicast = cast(mNclisum, Framework~variable, "sum")

##Standalones

stand = Nonclient[Nonclient$Framework=="STANDALONE",]
##DOUBLE CHECK YOU ARE SLICING THE RIGHT COLS!!!!!
stand = stand[,3:13]
stand$Framework = "Standalone"
mstand = melt(stand, id.vars = "Framework")
mstandsum = summarise(group_by(mstand, Framework, variable), count = sum(value))
standcast = cast(mstandsum,Framework~variable, "sum")

castframe = rbind(clientcast, Nclicast, standcast)
rownames(castframe) = castframe$Framework
castframe = castframe[,2:12]

##GROUP OUTM TOGETHER

group_outM = function(castdf)
{
  castdf$CodeView = castdf$`Decompiled CV` + castdf$`Assembly CV` + castdf$`Highlighted segments`
  castdf = subset(castdf, select = -c(`Decompiled CV`,`Assembly CV`, `Highlighted segments`))
  
  castdf$Text = castdf$`command line` + castdf$`Console log` + castdf$Table
  castdf = subset(castdf, select = -c(`command line`,`Console log`, Table))
  
  castdf$Visualization = castdf$`Graph vis` + castdf$Image +castdf$`GUI Window` 
  castdf = subset(castdf, select = -c(`Graph vis`,Image,`GUI Window` ))
  
  castdf$LaunchTool = castdf$`Launches client plugin`
  castdf$FileChange = castdf$`File creation / modification`
  castdf = subset(castdf, select = -c(`Launches client plugin`,`File creation / modification` ))
  return(castdf)
}

G1frame = group_outM(G1frame)
Funcframe = group_outM(Funcframe)
castframe = group_outM(castframe)


##Check output for which omnibus tests are significant to match final pvalues to comparisons
##CHISQ AGAINST OUTPUT METHOD

##First check if omnibus is significant
chisq = chisq.test(G1frame)

chisq$p.value
G1inP = chisq$p.value

if(G1inP<0.05)
{
  
  print("G1 omnibus test was significant!")
  #If val is sig move onto pairwise comps
  #f1 is Overview vs Subcomponent
  f1 = G1frame[2:3,]
  #f2 is Overview vs Experimentation
  f2 = G1frame[1:2,]
  #f3 is Subcomponent vs Experimentation
  f3 = G1frame[c(1,3),]
  
  
  f1p1 = subset(f1, select = c(FileChange, CodeView))
  f1p2 = subset(f1, select = c(FileChange, Text))
  f1p3 = subset(f1, select = c(FileChange, Visualization))
  f1p4 = subset(f1, select = c(CodeView, Text))
  f1p5 = subset(f1, select = c(CodeView, Visualization))
  f1p6 = subset(f1, select = c(Text, Visualization))
  
  f2p1 = subset(f2, select = c(FileChange, CodeView))
  f2p2 = subset(f2, select = c(FileChange, Text))
  f2p3 = subset(f2, select = c(FileChange, Visualization))
  f2p4 = subset(f2, select = c(CodeView, Text))
  f2p5 = subset(f2, select = c(CodeView, Visualization))
  f2p6 = subset(f2, select = c(Text, Visualization))
  
  f3p1 = subset(f3, select = c(FileChange, CodeView))
  f3p2 = subset(f3, select = c(FileChange, Text))
  f3p3 = subset(f3, select = c(FileChange, Visualization))
  f3p4 = subset(f3, select = c(CodeView, Text))
  f3p5 = subset(f3, select = c(CodeView, Visualization))
  f3p6 = subset(f3, select = c(Text, Visualization))
  
  cf1p1 = chisq.test(f1p1)
  cf1p2 = chisq.test(f1p2)
  cf1p3 = chisq.test(f1p3)
  cf1p4 = chisq.test(f1p4)
  cf1p5 = chisq.test(f1p5)
  cf1p6 = chisq.test(f1p6)
  
  cf2p1 = chisq.test(f2p1)
  cf2p2 = chisq.test(f2p2)
  cf2p3 = chisq.test(f2p3)
  cf2p4 = chisq.test(f2p4)
  cf2p5 = chisq.test(f2p5)
  cf2p6 = chisq.test(f2p6)
  
  
  cf3p1 = chisq.test(f3p1)
  cf3p2 = chisq.test(f3p2)
  cf3p3 = chisq.test(f3p3)
  cf3p4 = chisq.test(f3p4)
  cf3p5 = chisq.test(f3p5)
  cf3p6 = chisq.test(f3p6)
  
  pvals = list(G1inP, cf1p1$p.value, cf1p2$p.value, cf1p3$p.value, cf1p4$p.value, cf1p5$p.value, cf1p6$p.value,
               cf2p1$p.value, cf2p2$p.value, cf2p3$p.value, cf2p4$p.value, cf2p5$p.value, cf2p6$p.value,
               cf3p1$p.value, cf3p2$p.value, cf3p3$p.value, cf3p4$p.value, cf3p5$p.value, cf3p6$p.value)
  
  chis = list(chisq$statistic, cf1p1$statistic, cf1p2$statistic, cf1p3$statistic, cf1p4$statistic, cf1p5$statistic, cf1p6$statistic,
              cf2p1$statistic, cf2p2$statistic, cf2p3$statistic, cf2p4$statistic, cf2p5$statistic, cf2p6$statistic,
              cf3p1$statistic, cf3p2$statistic, cf3p3$statistic, cf3p4$statistic, cf3p5$statistic, cf3p6$statistic )
}else
{
  pvals = list(G1inP)
  chis = list(chisq$statistic)
}

##Do it again for Framework

chisq = chisq.test(castframe)

chisq$p.value
frameP = chisq$p.value

if(frameP<0.05)
{
  print("Framework omnibus was significant!")
  #If val is sig move onto pairwise comps
  #f1 is integrated vs Standalone
  f1 = castframe[2:3,]
  #f2 is Client vs Integrated
  f2 = castframe[1:2,]
  #f3 is Client vs Standalone
  f3 = castframe[c(1,3),]
  
  f1p1 = subset(f1, select = c(FileChange, CodeView))
  f1p2 = subset(f1, select = c(FileChange, Text))
  f1p3 = subset(f1, select = c(FileChange, Visualization))
  f1p4 = subset(f1, select = c(CodeView, Text))
  f1p5 = subset(f1, select = c(CodeView, Visualization))
  f1p6 = subset(f1, select = c(Text, Visualization))
  
  f2p1 = subset(f2, select = c(FileChange, CodeView))
  f2p2 = subset(f2, select = c(FileChange, Text))
  f2p3 = subset(f2, select = c(FileChange, Visualization))
  f2p4 = subset(f2, select = c(CodeView, Text))
  f2p5 = subset(f2, select = c(CodeView, Visualization))
  f2p6 = subset(f2, select = c(Text, Visualization))
  
  f3p1 = subset(f3, select = c(FileChange, CodeView))
  f3p2 = subset(f3, select = c(FileChange, Text))
  f3p3 = subset(f3, select = c(FileChange, Visualization))
  f3p4 = subset(f3, select = c(CodeView, Text))
  f3p5 = subset(f3, select = c(CodeView, Visualization))
  f3p6 = subset(f3, select = c(Text, Visualization))
  
  cf1p1 = chisq.test(f1p1)
  cf1p2 = chisq.test(f1p2)
  cf1p3 = chisq.test(f1p3)
  cf1p4 = chisq.test(f1p4)
  cf1p5 = chisq.test(f1p5)
  cf1p6 = chisq.test(f1p6)
  
  cf2p1 = chisq.test(f2p1)
  cf2p2 = chisq.test(f2p2)
  cf2p3 = chisq.test(f2p3)
  cf2p4 = chisq.test(f2p4)
  cf2p5 = chisq.test(f2p5)
  cf2p6 = chisq.test(f2p6)
  
  
  cf3p1 = chisq.test(f3p1)
  cf3p2 = chisq.test(f3p2)
  cf3p3 = chisq.test(f3p3)
  cf3p4 = chisq.test(f3p4)
  cf3p5 = chisq.test(f3p5)
  cf3p6 = chisq.test(f3p6)
  
  pvals = append(pvals, c(frameP, cf1p1$p.value, cf1p2$p.value, cf1p3$p.value, cf1p4$p.value, cf1p5$p.value, cf1p6$p.value,
                          cf2p1$p.value, cf2p2$p.value, cf2p3$p.value, cf2p4$p.value, cf2p5$p.value, cf2p6$p.value,
                          cf3p1$p.value, cf3p2$p.value, cf3p3$p.value, cf3p4$p.value, cf3p5$p.value, cf3p6$p.value))
  
  chis = append(chis, list(chisq$statistic, cf1p1$statistic, cf1p2$statistic, cf1p3$statistic, cf1p4$statistic, cf1p5$statistic, cf1p6$statistic,
                           cf2p1$statistic, cf2p2$statistic, cf2p3$statistic, cf2p4$statistic, cf2p5$statistic, cf2p6$statistic,
                           cf3p1$statistic, cf3p2$statistic, cf3p3$statistic, cf3p4$statistic, cf3p5$statistic, cf3p6$statistic ))
}else
{
  print("Appending: ")
  print(frameP)
  pvals = append(pvals, frameP)
  chis = append(chis, chisq$statistic)
}

##Now finaly for Static vs Dynamic

chisq = chisq.test(Funcframe)

chisq$p.value
funcP = chisq$p.value

if(funcP<0.05)
{
  #If val is sig move onto pairwise comps
  print("Functionality type omnibus is significant")
  f1 = Funcframe[1:2,]
  
  f1p1 = subset(f1, select = c(FileChange, CodeView))
  f1p2 = subset(f1, select = c(FileChange, Text))
  f1p3 = subset(f1, select = c(FileChange, Visualization))
  f1p4 = subset(f1, select = c(CodeView, Text))
  f1p5 = subset(f1, select = c(CodeView, Visualization))
  f1p6 = subset(f1, select = c(Text, Visualization))
  
  cf1p1 = chisq.test(f1p1)
  cf1p2 = chisq.test(f1p2)
  cf1p3 = chisq.test(f1p3)
  cf1p4 = chisq.test(f1p4)
  cf1p5 = chisq.test(f1p5)
  cf1p6 = chisq.test(f1p6)
  
  pvals = append(pvals, c( funcP, cf1p1$p.value, cf1p2$p.value, cf1p3$p.value, cf1p4$p.value, cf1p5$p.value, cf1p6$p.value))
  chis = append(chis, list(chisq$statistic, cf1p1$statistic, cf1p2$statistic, cf1p3$statistic, cf1p4$statistic, cf1p5$statistic, cf1p6$statistic))
}else
{
  print("Appending: ")
  print(funcP)
  pvals = append(pvals, funcP)
  chis = append(chis, chisq$statistic)
}

##Finally correct the pvalues!
print("Final Output Content Chi Squared results")
print(p.adjust(pvals, method="BH", n = length(pvals)))


## Code to produce the bars used to create Figure 4 in Section 5 of the paper. 
bound$G1 = ordered(bound$G1, levels = c("Experimentation", "Subcomponent", "Overview"))

p = ggplot(bound, aes(fill = G1,x =variable, y= count))+ geom_bar(stat = "identity")
p = p + theme(plot.margin = unit(c(1,1,1,1), "cm"),text=element_text(family="Arial",size=12),legend.position="bottom",panel.grid.major.y=element_blank(), panel.grid.major.x=element_line(colour="black"),panel.grid.minor=element_blank(),panel.background = element_rect(fill="white"),axis.text.y=element_text(colour = "black"),axis.text.x=element_text(colour = "black"),axis.ticks.y=element_blank(),axis.title.y=element_blank(),axis.title.x=element_blank())
p + coord_flip()+scale_fill_brewer(palette = "Set1")

##*********** End of Output Method Chi Squared tests *********** 





### ***********  Start of code for generating Logistic Models ****************

## LATEX CODE FOR VIEWING MODELS ##
## This code must be run to define the "make_model_tbl_lm" function used to display model results in the subsequent code blocks.

CI_fmt <- Vectorize(function(m, se){
  lower <- round(exp(m - 1.96 * se), 5)
  upper <- round(exp(m + 1.96 * se), 5)
  paste0("[", lower, ", ", upper, "]")
})

makeCI <- function(model, sigdigits = 2){
  tidy(model) %>%
    mutate(CI = CI_fmt(estimate, std.error))
}

# Making the LaTeX tables (if you run this you'll get output of Latex Code for tables to put in your files)
library(broom)
library(xtable)
library(dplyr)

make_model_tbl <- function(model){
  star = ifelse(model$p.value < 0.05, "*", "")
  exp_Coef = exp(model$estimate)
  model$p.value = ifelse(model$p.value < 0.001, "< 0.001", as.character(round(model$p.value, 3)))
  model$p.value = paste0(model$p.value, star)
  CI = CI_fmt(model$estimate, model$std.error)
  final_df <- data.frame(model$term, exp_Coef, CI, model$p.value)
}

make_model_tbl_lm <- function(model, val){
  coef_table <- summary(model)$coefficients
  coef_table <- coeftest(model)
  term <- rownames(coef_table)
  estimate <- as.numeric(coef_table[,"Estimate"])
  std.error <- as.numeric(coef_table[,"Std. Error"])
  z.value <- as.numeric(coef_table[,paste(val," value",sep="")])
  p.value <- as.numeric(coef_table[,paste("Pr(>|",val,"|)",sep="")])
  coef_df <- data.frame(term,estimate,std.error,z.value,p.value)
  
  star = ifelse(coef_df$p.value < 0.05, "*", "")
  # exp_Coef = exp(abs(coef_df$estimate)) * sign(coef_df$estimate)
  exp_Coef = exp(coef_df$estimate)
  coef_df$p.value = ifelse(coef_df$p.value < 0.001, "< 0.001", as.character(round(coef_df$p.value, 3)))
  coef_df$p.value = paste0(coef_df$p.value, star)
  CI = CI_fmt(coef_df$estimate, coef_df$std.error)
  final_df <- data.frame(coef_df$term, exp_Coef, CI, coef_df$p.value)
}


## The next blocks subset from logdf to then run our five regression models. The model results for G1 are reported in the appendix in Table 12.
sublog = subset(logdf, select =  c("G1", "G2", "G3", "G4", "G5","both", "Overview", "Subcomponent", "Experimentation"))
print("Results for G1 model")
##G1
mylog = glm(G1~Overview+Subcomponent+Experimentation, data = sublog, family = "binomial")
summary(mylog)
print(make_model_tbl_lm(mylog, "z"))


## Regression model for G2 reported in section 7 in Table 6. Before executing the following code blocks, make sure "sublog" exists by running the 
## above block to generate the model for G1
##G2
print("Results for G2 model")
mylog = glm(G2~Subcomponent, data = sublog, family = "binomial")
summary(mylog)
print(make_model_tbl_lm(mylog, "z"))


## Regression model for G3 reported in section 7 in Table 6.
##G3
print("Results for G3 model")
mylog = glm(G3~Overview+Subcomponent+both, data = sublog, family = "binomial")
summary(mylog)
print(make_model_tbl_lm(mylog, "z"))


## Regression model for G4 reported in section 7 in Table 6.
##G4
print("Results for G4 model")
mylog = glm(G4~Experimentation, data = sublog, family = "binomial")
summary(mylog)
print(make_model_tbl_lm(mylog, "z"))


## Regression model for G5 reported in section 7 in Table 6.
##G5
print("Results for G5 model")
mylog = glm(G5~Experimentation+both, data = sublog, family = "binomial")
summary(mylog)
print(make_model_tbl_lm(mylog, "z"))


