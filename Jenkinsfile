@Library('dst-shared@master') _
 
dockerBuildPipeline {
    app = "bss-ipxe"
    name = "ipxe"
    description = "Cray Management System iPXE binaries"
    repository = "cray"
    imagePrefix = "cray"
    product = "csm"
    
    githubPushRepo = "Cray-HPE/cms-ipxe"
    /*
        By default all branches are pushed to GitHub

        Optionally, to limit which branches are pushed, add a githubPushBranches regex variable
        Examples:
        githubPushBranches =  /master/ # Only push the master branch
        
        In this case, we push bugfix, feature, hot fix, master, and release branches
    */
    githubPushBranches =  /(bugfix\/.*|feature\/.*|hotfix\/.*|master|release\/.*)/ 
}
