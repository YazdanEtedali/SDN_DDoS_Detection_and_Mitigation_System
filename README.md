# Project Story: Intelligent Network Traffic Controller

## Introduction

In the rapidly evolving world of network management, ensuring seamless, secure, and efficient traffic flow is a critical challenge. Recognizing the need for smarter network management solutions, our team embarked on a journey to develop an Intelligent Network Traffic Controller using the Ryu SDN framework and machine learning models. This project aimed to create a system capable of real-time traffic analysis, anomaly detection, and automated responses to ensure optimal network performance.

## Phase 1: Conceptualization and Planning

The project began with extensive research and brainstorming sessions to identify the key objectives and scope. We aimed to leverage Software Defined Networking (SDN) for its flexibility and programmability. The Ryu SDN controller was chosen as our foundation due to its robust capabilities and active community support. Additionally, we decided to integrate machine learning to enhance the controller's ability to detect and mitigate network anomalies.

## Phase 2: Building the Foundation

With a clear plan in place, we started by setting up the Ryu SDN controller environment. We explored various features of the Ryu framework, understanding its architecture and functionalities. The initial phase involved writing basic Ryu applications to manage simple network flows, laying the groundwork for more complex features.

## Phase 3: Feature Implementation

We then moved on to implementing advanced features. This phase involved:

- **MAC Learning and Traffic Forwarding:** We developed a mechanism to learn MAC addresses and efficiently forward packets, reducing unnecessary flooding in the network.
- **Service Identification:** By analyzing packet headers, we mapped ports to known services (e.g., HTTP, FTP) and categorized the traffic accordingly.
- **Feature Extraction:** Critical network metrics such as `src_bytes`, `srv_count`, `count`, and various rates were computed in real-time. These features formed the basis for traffic analysis and anomaly detection.

## Phase 4: Integrating Machine Learning

To enable intelligent decision-making, we integrated a pre-trained CatBoost model. The model was designed to classify network traffic as "normal" or potentially malicious. This phase involved:

- **Feature Engineering:** Ensuring that the extracted features were suitable inputs for the model.
- **Model Integration:** Seamlessly integrating the CatBoost model with the Ryu controller to make real-time predictions based on the incoming traffic.
- **Automated Actions:** Implementing logic to forward or drop packets based on the model's predictions, enhancing network security and performance.

## Phase 5: Real-time Monitoring and Updates

To ensure the controller's responsiveness to changing network conditions, we implemented periodic flow updates. This involved deleting old flows and adding new ones, keeping the network state fresh and optimized. Additionally, features were continuously logged to a CSV file for further analysis and fine-tuning of the model.

## Phase 6: Testing and Validation

Extensive testing was conducted in simulated network environments on Mininet to validate the controller's functionality. We monitored its performance, accuracy of the machine learning predictions, and its ability to handle various traffic scenarios. The controller successfully demonstrated its ability to manage traffic intelligently, detect anomalies, and take appropriate actions.

## Conclusion

The project culminated in a sophisticated Intelligent Network Traffic Controller capable of real-time traffic management and anomaly detection. By combining the power of SDN with machine learning, we created a system that not only optimizes network performance but also enhances security. This journey was a testament to the potential of interdisciplinary approaches in solving complex network challenges. the naration video will soon be uploaded on my youtube channel . feel free to contact me and ask questions . 


## how to test ?:

by running the aycmp.py file using ryu manager and mininet to start a topology the two scenarios will be connected to each other and each packet will be sent into the controller for analysis and policy making . you can test on normal data by iperf or http requests like curl or wget and attack traffic with hping3 . 
