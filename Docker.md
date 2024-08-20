
- Containers - 
    A container is a lightweight, standalone, and executable package that includes everything needed to run a piece of software
 
    1. Isolation
        Containers provide process and filesystem isolation, meaning each container runs in its own environment and does not interfere with others. This isolation is achieved using features of the operating system's kernel, such as namespaces and cgroups in Linux.

    2. Portability
        Because containers encapsulate all dependencies and configuration, they can be moved and run consistently across different environments, including  development, testing, staging, and production. This eliminates the “it works on my machine” problem.

    3. Lightweight
        Containers share the host system’s kernel and use a small footprint compared to virtual machines (VMs). They do not require a full operating system per instance, which makes them more efficient in terms of resource usage and startup time.
   
    4. Image-Based
        Containers are created from images, which are read-only templates that include everything needed to run an application. Images are built using Dockerfiles or similar definitions and can be stored in container registries. When a container is run, it starts from an image and adds a writable layer on top.


- Containers vs VM's -

    Containers and virtual machines (VMs) are both technologies used for running applications in isolated environments, but they differ significantly in their architecture, resource usage, and management. 

    1. Architecture
        
        Containers:

            Isolation: Containers share the host operating system’s kernel. They use OS-level virtualization features like namespaces and cgroups to provide process and filesystem isolation.
            
            Image: Containers are created from images that include the application and its dependencies but use the host's OS kernel.

        VMs:

            Isolation: VMs use hardware virtualization to run separate operating systems on top of a hypervisor (e.g., VMware ESXi, Microsoft Hyper-V, KVM). Each VM includes a full OS along with its own kernel.
            
            Image: VMs are created from virtual machine images that include a full operating system, application, and all dependencies.



    2. Resource Usage
        
        Containers:

            Lightweight: Containers share the host OS kernel and typically use fewer resources. They have a smaller footprint compared to VMs and can start up quickly.

            Efficiency: Containers are more efficient in terms of memory and CPU usage because they do not need to run a full OS.
    
        VMs:

            Heavyweight: VMs include a full OS, which requires more disk space and memory. Each VM runs its own OS instance, leading to higher resource consumption.
        
            Overhead: The additional overhead of running multiple OS instances can result in slower startup times and increased resource usage.


    3. Performance
    
        Containers:

            Performance: Containers generally offer better performance because they have less overhead. They share the host OS kernel, which reduces the need for extensive virtualization.
        
            Startup Time: Containers can start almost instantly since they do not require booting a full OS.
        
        VMs:

            Performance: VMs can be slower due to the overhead of running a full OS and the virtualization layer. They often have higher latency compared to containers.
        
            Startup Time: VMs typically take longer to start as they need to boot up a full operating system.



    4. Management
    
        Containers:

            Deployment: Containers are easier to deploy and manage due to their lightweight nature. Tools like Docker and Kubernetes provide robust container orchestration and management.

            Consistency: Containers ensure consistent environments from development to production by packaging all dependencies together.

        VMs:

            Deployment: VMs require more management because they involve handling full operating systems and hypervisors. Tools like VMware vSphere and Microsoft System Center manage VMs.
        
            Consistency: VMs provide consistency at the OS level, but they are heavier and can be more complex to manage.



- Images vs. Containers:
    Images are like the blueprint or recipe of the application. Images are Immutable and are built in layers and are reusable in different environments.
    
    Containers are the actual running instances based on that blueprint.



- Dockerfile Basics:
    https://docs.google.com/spreadsheets/d/1nY1IM4WxsLTpiD5Xgug7P4jL1cGDBlbaZj9EVr3_t_M/edit?gid=0#gid=0

    FROM        - 	Creates a layer |	Build Time	|   Base image to use for the Docker image	                      |     FROM ubuntu:20.04
    
    RUN	        -   Creates a layer |	Build Time	|   Executes commands to customize the image	                  |     RUN apt-get update && apt-get install -y python3
    
    COPY        -	Creates a layer |	Build Time	|   Copies files from the host to the container                   |   	COPY myapp.py /app/myapp.py
    
    ADD	        -   Creates a layer |	Build Time	|   Copies files, extracts archives, or downloads files           | 	ADD archive.tar.gz /app/
    
    WORKDIR     -	Creates a layer |	Build Time	|   Sets the working directory inside the container	              |     WORKDIR /app
    
    CMD	        -   No	            |   Run Time	|   Provides the default command to run when the container starts | 	CMD ["python3", "myapp.py"]
    
    ENTRYPOINT  - 	No	            |   Run Time	|   Sets the default executable for the container	              |     ENTRYPOINT ["python3"]
    
    ENV	        -   Creates a layer |	Build Time	|   Sets environment variables inside the container	              |     ENV APP_ENV=production
    
    EXPOSE	    -   No              | 	Run Time	|   Documents the port the container listens on	                  |     EXPOSE 80
    
    VOLUME	    -   No             	|   Run Time	|   Defines a mount point for external volumes                    | 	VOLUME ["/data"]
    
    USER	    -   Creates a layer |	Build Time	|   Specifies the user for running container processes            | 	USER myuser

    SHELL        -  Creates a layer |   Build Time  |   Specifies the shell to use for subsequent RUN commands.      |  SHELL ["powershell", "-command"]

    STOPSIGNAL  -   No              |   Run Time    |   Sets system call signal that willbe sent to the container to exit |    STOPSIGNAL SIGTERM

    ARG         -   Creates a layer |   Build Time  |   A variable that users can pass at buildtime with the docker build command | ARG VERSION=1.0

    ONBUILD     -   Creates a layer |   Build Time  |   Adds a trigger instruction to the image, executed when the image is used as a base for another  build.   |   ONBUILD RUN apt-get update && apt-get install -y build-essential

    LABEL       -   Creates a layer |   Build Time  |   Adds metadata to an image in the form of key-value pairs. Useful for organizing and managing images. |          LABEL maintainer="mdabrar@example.com"


    HEALTHCHECK -   No              |   Run Time    |   Defines a command that Docker uses to check the health of a running container. | HEALTHCHECK --interval=5m --timeout=3s CMD curl -f http://localhost/ || exit 1


    CACHEBUST   -   Creates a layer  |  Build Time  |   A common practice to force Docker to re-run specific layers, useful in development.      |          ARG    CACHEBUST=1
                                 RUN apt-get update && apt-get install -y python3



- Dockerfile Optimization

    Cache Lookup: Docker checks its cache to see if it has already built a layer with the same instruction and the same set of files or dependencies.
    Cache Hit: If Docker finds an existing layer that matches, it reuses that cached layer instead of rebuilding it. 
    Cache Miss: If Docker cannot find a matching cached layer (due to changes in the instruction, files, or dependencies), it rebuilds the layer and invalidates the cache for all subsequent layers.

    1. Order Dockerfile Instructions Strategically. Stable commands like installing system dependencies at the top of the Dockerfile and Frequent changes last such as copying source code

    2. Minimize the Number of Layers. Combine Commands, Use a single RUN instruction to execute multiple commands, reducing the number of layers created. Clean Up in the Same Layer: Perform cleanup   actions (like removing unnecessary files) within the same RUN instruction to avoid creating additional layers. 
        
        Ex: RUN apt-get update && apt-get install -y \
            curl \
            git \
            && apt-get clean \
            && rm -rf /var/lib/apt/lists/*

    3. Leverage COPY and ADD Efficiently
        
        Copy Dependencies Separately: Copy files related to dependencies (like package.json or requirements.txt) before copying the application source code. This ensures that changes in the source code don’t invalidate the cache for dependencies.
        
        Use .dockerignore: Exclude unnecessary files from being copied into the image by using a .dockerignore file. This prevents unnecessary cache invalidation and keeps the image size smaller.

    4. Use Multi-Stage Builds, 
        Separate Build and Runtime Stages: Multi-stage builds allow you to split the build process into stages, caching dependencies separately from the application code and reducing the final image size. Optimize Cache, By isolating stages, you can cache intermediate stages (like dependency installation) and only rebuild what’s necessary when the source code changes.

- Docker CLI Commands

    By default, Docker stores all its data in /var/lib/docker. This includes images, containers, volumes, and networks. If you want to change this path, you can configure the Docker daemon to use a different directory.

    Configurations are stored in /etc/docker/daemon.json. restart docker service after the changes

    - 1. General Commands
        docker --version
        Displays the Docker version installed on your system.

        docker info
        Provides detailed information about the Docker installation, including system-wide and container-specific information.

    - 2. Docker Images
        docker pull <image>
        Downloads an image from Docker Hub or another registry.

        docker build -t <tag> <path>
        Builds a Docker image from a Dockerfile located at <path>. The -t option tags the image with <tag>.

        docker images
        Lists all images on your local system.

        docker rmi <image>
        Removes an image from your local system.

        docker tag <image> <repository>:<tag>
        Tags an image with a new name or tag, which is useful for organizing and versioning.

    - 3. Docker Containers
        docker run [options] <image> [command]
        Creates and starts a new container from an image. You can specify options like -d (detached mode), -p (port mapping), -v (volume mounting), etc.

        docker ps
        Lists all running containers.

        docker ps -a
        Lists all containers, including those that are stopped.

        docker exec -it <container> <command>
        Executes a command in a running container. The -it option allows interactive terminal access.

        docker stop <container>
        Stops a running container.

        docker start <container>
        Starts a stopped container.

        docker restart <container>
        Restarts a running or stopped container.

        docker rm <container>
        Removes a container from the system. The container must be stopped before it can be removed.

        docker logs <container>
        Fetches the logs from a container.

    - 4. Docker Networks
        docker network ls
        Lists all Docker networks on your system.

        docker network inspect <network>
        Displays detailed information about a specific network.

        docker network create <network>
        Creates a new Docker network.

        docker network rm <network>
        Removes a Docker network.

    - 5. Docker Volumes
        docker volume ls
        Lists all Docker volumes on your system.

        docker volume inspect <volume>
        Displays detailed information about a specific volume.

        docker volume create <volume>
        Creates a new Docker volume.

        docker volume rm <volume>
        Removes a Docker volume.

    - 6. Docker Compose
        docker-compose up
        Starts containers as defined in a docker-compose.yml file. Use -d for detached mode.

        docker-compose down
        Stops and removes containers, networks, and volumes defined in a docker-compose.yml file.

        docker-compose build
        Builds or rebuilds services defined in a docker-compose.yml file.

        docker-compose logs
        Shows logs for services defined in a docker-compose.yml file.

        docker-compose exec <service> <command>
        Executes a command in a running service container.

    - 7. Docker Registries
        docker login
        Logs into a Docker registry.

        docker logout
        Logs out from a Docker registry.

        docker push <image>
        Pushes an image to a Docker registry.

        docker pull <image>
        Pulls an image from a Docker registry.


- Exceptions

    Running a root or super user command in a container - By default if no user is provided, docker container runs as a root user

    - Option 1 - Switch to root user and come back to normal user

        FROM ubuntu:20.04
        RUN useradd -m myuser
        USER myuser
        USER root
        RUN apt-get update && apt-get install -y some-package
        USER myuser
        CMD ["bash"]


    - Option 2 - Run the container as a root user

        docker run -it --user root my-image bash

        
    - Option 3 - Execute command as root user

        docker exec -u root -it <container_id_or_name> bash
                            
                              or

        docker exec -u root <container_id_or_name> <command>






- Multi-Stage Builds in docker
 
    # Stage 1
        FROM golang:1.20 AS builder

        WORKDIR /app

        COPY . .

        RUN go build -o myapp

    # Stage 2: Create the final image
        FROM alpine:3.16

        WORKDIR /app

        COPY --from=builder /app/myapp .

        CMD ["./myapp"]


    - Benefits
            Reduced Image Size: Only the files and dependencies required at runtime are included in the final image. Build tools and intermediate files are discarded.
            Improved Build Performance: By using specific images for different stages, you can cache layers more efficiently, speeding up rebuilds.
            Cleaner Dockerfile: Separates concerns by keeping the build process and runtime environment distinct, making the Dockerfile easier to understand and maintain.

    - Advanced Use Cases
            Multi-Language Builds: You can use different base images for various stages, such as one for building and another for running.




- Docker networking

    - Docker Networking Modes

        -  Bridge Network:   Containers on the same bridge network can communicate with each other using their container names. By default, containers on different bridge networks cannot communicate.
        
        -  Host Network:     The container shares the host’s networking namespace and there is no network isolation between the host and the container.
        
        -  None Network:     Useful for security purposes when the container doesn’t need network access.
        
        -  Overlay Network:  Used in Docker Swarm mode to connect containers running on different Docker hosts

        -  Macvlan Network:  Assigns a MAC address to each container, making it appear as a physical device on the network.

        
        
    - Custom Docker networks

        -  create an isolated network where containers can communicate via DNS       "docker network create --driver bridge my_custom_network"

        -  Connect a container to multiple networks                                  "docker network connect my_custom_network container_name"

    
    -  Network Security
        
        -   Network Policies: Control which containers can communicate with each other.
        
        -   Ingress Network: Used in Swarm mode to handle incoming requests to a service.
        
        -   Network Encryption: Overlay networks in Docker Swarm can be encrypted to secure data in transit between nodes.

        
    -  Network Scopes

    -    Local Scope:   Networks that are restricted to a single host (e.g., bridge, host, macvlan).
    
    -    Global Scope:   Networks that span across multiple Docker hosts (e.g., overlay networks in Docker Swarm).

- Docker security
 
    1. Namespace Isolation
        
        Linux Namespaces: A Linux namespace is a feature of the Linux kernel that isolates and virtualizes system resources for processes. Namespaces allow processes to have their own separate instances of certain global resources, which helps in creating containers and other forms of virtualization.
        
        Docker containers use Linux namespaces to provide isolation between processes, users, network interfaces, and file systems. 
        
        Key namespaces include:
            
            PID Namespace: Isolates process IDs, ensuring that processes within a container are independent of those on the host.
            
            NET Namespace: Provides each container with its own network stack, including interfaces, routing tables, and IP addresses.
            
            MNT Namespace: Isolates the file system, ensuring containers have their own view of the file system hierarchy.
            
            UTS Namespace: Allows containers to have their own hostname and domain name, independent of the host.

            IPC Namespace: Isolates inter-process communication resources, like message queues and semaphores.

            USER Namespace: Isolates user and group IDs, allowing a process to have different user IDs in different namespaces.

            CGROUP Namespace: Isolates the view of control groups (cgroups), which are used for resource limiting, prioritization, and accounting.

    2. Control Groups (cgroups)
        
        Control groups, or cgroups, are a Linux kernel feature that allows administrators to allocate, manage, and monitor system resources (such as CPU, memory, disk I/O, and network bandwidth) for a set of processes. Cgroups provide a way to group processes together and apply resource limits and usage constraints, ensuring that certain groups of processes don't overconsume system resources and impact the overall system performance.

        Resource Limitation: 
            
            Docker uses cgroups to limit the resources (CPU, memory, I/O) that a container can use. This prevents a single container from monopolizing system resources and potentially causing a denial-of-service (DoS) attack on the host.

    3. Capabilities and Privileges
        
        Dropping Capabilities: 
            By default, Docker containers run with a reduced set of Linux capabilities. You can drop additional capabilities to minimize what the container can do.
            
            Example: Drop all capabilities except those necessary for the container.
            docker run --cap-drop=ALL --cap-add=NET_ADMIN my_container
        

        Rootless Containers:
            Running containers as a non-root user (rootless mode) increases security by preventing containers from having root privileges on the host.

        
        - Common Capabilities:

            docker inspect --format='{{.HostConfig.CapAdd}}' <container_id_or_name>

            -   Capabilities NOT Included by Default:
                    
                    Some powerful capabilities are not included by default, and you need to explicitly add them using --cap-add if your container requires them. These include:

                    CAP_SYS_ADMIN: Broad system administration capabilities.

                    CAP_NET_ADMIN: Network management capabilities.

                    CAP_SYS_TIME: Ability to modify the system clock.

                    CAP_SYS_PTRACE: Ability to trace or debug processes.

                
            -   CAP_CHOWN:

                    Allows the process to change the ownership of files.
                    Useful if the container needs to change file ownerships, which is usually a privileged operation.
            
            -   CAP_DAC_OVERRIDE:

                    Allows the process to bypass file read, write, and execute permission checks.
                    This can be useful if a container needs to access files with restricted permissions.
                    
            -   CAP_FOWNER:

                    Allows the process to bypass permission checks on operations that normally require file ownership.
                    Useful for containers that need to modify files owned by other users.
            
            -   CAP_KILL:

                    Allows the process to send signals to processes that it does not own.
                    Typically needed if the container needs to manage or terminate other processes.
            
            -   CAP_SYS_ADMIN:

                    A broad and powerful capability that allows the process to perform a range of system administration tasks, including mounting filesystems, managing quotas, and setting the hostname.
                    Often considered dangerous due to its broad permissions, so it should be used with caution.
                    
            -   CAP_SYS_TIME:

                    Allows the process to change the system clock.
                    Useful if the container needs to manage or modify the system time.
            
            -   CAP_NET_RAW:

                    Allows the process to use raw sockets.
                    Necessary for containers that need to create custom network protocols or tools like ping.
                    
            -   CAP_SYS_PTRACE:

                    Allows the process to trace or debug other processes.
                    Useful for debugging or monitoring other processes within the container.
                    
            -   CAP_MKNOD:

                    Allows the process to create special files using the mknod system call.
                    Needed if the container needs to create devices within its namespace.
                   
            -   CAP_AUDIT_WRITE:

                    Allows the process to write records to the kernel's audit log.
                    Useful for containers that need to interact with the system's audit framework.
                    
            -   CAP_NET_BIND_SERVICE:

                    Allows the process to bind to network ports below 1024.
                    Necessary for running services like HTTP (port 80) or HTTPS (port 443) that require access to lower-numbered ports.
                    
            -   CAP_IPC_LOCK:
                    Allows the process to lock memory in RAM, preventing it from being paged to disk.
                    Useful for containers that need to ensure that certain memory regions remain resident in RAM for performance or security reasons.
                
    4. Security Profiles

        -   Seccomp (Secure Computing Mode)

                Docker uses Seccomp profiles to restrict the system calls that containers can make.     ''' docker run --security-opt seccomp=/path/to/seccomp/profile.json my_container '''

        -   AppArmor profiles define what resources a container can access, such as files, network interfaces, and capabilities.     ''' docker run --security-opt apparmor=custom_profile my_container '''

        -   Selinux in case of Redhat based containers
    
    5. Image Security

            Trusted Images: Always use official or verified images from trusted sources. 

            Image Scanning: Use tools like Docker Security Scanning or third-party tools (e.g., Clair, Trivy) to scan images for known vulnerabilities before deploying them.
            
            Minimized Base Images: Use minimal base images (e.g., alpine, scratch) to reduce the attack surface by limiting the number of installed packages.
    
    6. Container Hardening

            Container image hardening is a process of securing a container by reducing its attack surface and making it less vulnerable to exploits.

            Read-Only Filesystem: Run containers with a read-only file system to prevent unauthorized changes to the file system during runtime.
                docker run --read-only my_container
            
            Immutable Infrastructure: Treat containers as immutable; if a container needs an update, rebuild and redeploy rather than modifying it in place.

    7. Audit and Monitoring

            Docker Bench Security: Run the Docker Bench for Security script to audit your Docker environment against best practices.
            Logging: Enable and monitor logs for container activities, and integrate with centralized logging systems like ELK (Elasticsearch, Logstash, Kibana) or Prometheus.
            Monitoring Tools: Use monitoring tools like Falco to detect unexpected behavior or security breaches in real-time.

    8. Access Control
        
            Role-Based Access Control (RBAC): Implement RBAC in Docker Swarm or Kubernetes to restrict user actions based on their roles.
            Least Privilege Principle: Grant the minimum necessary permissions to users, processes, and containers.

    9. Notary and Content Trust
            
            Use Docker Content Trust (DCT) to sign images and ensure that only trusted images are deployed in your environment. ''' export DOCKER_CONTENT_TRUST=1 '''

    10. Regular Updates and Patch Management
        
            Regularly update Docker, your host OS, and container images to ensure they include the latest security patches.

- Docker Volumes

    Volumes are directories or files that exist outside the container's filesystem but are mounted into a container at a specified path. Unlike bind mounts, which map a specific directory from the host system into the container, volumes are managed by Docker and are stored in as part of the host filesystem that is managed by Docker (/var/lib/docker/volumes)


    - Types of Volumes 

        Anonymous Volumes              -   docker run -d --name my_container -v /app busybox    |           creates an anonymous volume that is mounted to /app in the container.

        Named Volumes                  -   docker volume create my_volume  ;     docker run -d --name my_container -v my_volume:/app busybox    |       creates a named volume called my_volume and mounts it to /app in the container.

        Host Volumes (Bind Mounts)     -   docker run -d --name my_container -v /path/on/host:/app busybox       |       binds the host directory /path/on/host to /app in the container

    - Mounting Volumes

        docker run -d --mount source=myvolume,target=/app/data myimage      or      docker run -d -v myvolume:/app/data myimage
    
    - Persistent Data Storage
        
        Using Named Volumes     "   docker run -d --name myapp -v mydata:/app/data myimage  "

        Backups and Restores    "   docker run --rm -v mydata:/app/data -v $(pwd):/backup busybox tar cvf /backup/backup.tar /app/data  "

        Data Migration          "   docker run --rm -v mydata:/data -v $(pwd):/backup busybox tar xvf /backup/backup.tar -C /data       "
    
    - Storage Drivers
        
        OverlayFS (Overlay2)    OverlayFS is a modern, efficient union filesystem that Docker uses by default on most Linux distributions. Overlay2 is its newer version.

        AUFS                    It supports multiple layers and has been widely used in the past.

        Device Mapper           Uses block-level storage to manage images and containers. It works differently from OverlayFS and AUFS, as it operates at the block level. Can be slower than OverlayFS due to its complexity to manage

        Btrfs                   A modern, copy-on-write filesystem that supports advanced features like snapshots, subvolumes, and compression.

        ZFS                     A high-performance filesystem that supports snapshots, clones, and advanced data integrity features. Often used in high-availability environments. Used in environments with large storage needs.

        -   How Storage Drivers Affect Performance:

            Layer Management: The efficiency with which a storage driver handles layers can significantly impact performance. Overlay2, for example, excels in managing layers efficiently, reducing the overhead associated with file operations.

            Copy-on-Write: Many storage drivers, like Overlay2 and AUFS, use copy-on-write, which reduces disk usage and speeds up container creation. However, the actual performance depends on how efficiently the storage driver implements this.

            Compatibility: Some storage drivers are more compatible with certain types of workloads or filesystems. For example, Overlay2 is optimized for Linux kernels that support it, while ZFS and Btrfs might be better suited for environments requiring advanced filesystem features.

- Docker Troubleshooting

    -   Accessing and monitoring logs
        
            docker logs my_container

            docker stats get real-time metrics about your containers.

            docker top my_container

            docker inspect my_container

            docker events                        events from the Docker daemon, such as container start, stop, and die events    

            docker system df                     disk usage of Docker images, containers, and volumes.

            journalctl -u docker.service         Views logs from the Docker daemon. Helpful for diagnosing issues with the Docker service itself

    -   Limiting CPU and memory usage

            docker run --cpus="1.5" my_image

            docker run --memory="512m" --memory-swap="1g" my_image
            