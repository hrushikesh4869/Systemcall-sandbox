#include<bits/stdc++.h>
#include<sys/ptrace.h>
#include<sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include<sys/user.h>
#include <unistd.h>
#include "syscall_mappings.h"
using namespace std;

map<string,vector<pair<string,string>>> makegraph(string automaton)
{
    ifstream fin;
    string line;
    map<string,vector<pair<string,string>>> graph;


    fin.open(automaton);
    while(getline(fin,line))
    {
        stringstream ss(line);
        string u,v,labl;
        ss>>u;
        ss>>v;
        ss>>labl;
        //cout<<labl<<endl;
        pair<string,string> node(v,labl);
        graph[u].push_back(node);
    }   
    fin.close(); 
    return graph;
}

vector<pair<string,string>> traversegraph(string start_node,map<string,int> &vis,map<string,vector<pair<string,string>>> graph)
{
    queue<string> q;
    vector<pair<string,string>> syscalls;

    q.push(start_node);
    while(!q.empty())
    {
        string s = q.front();
        q.pop();
        vis[s] = 1;
        vector<pair<string,string>> list = graph[s];
        for(int j = 0; j<list.size(); j++)
        {
            if(list[j].second != "-")
            {
               // cout<<"got syscall"<<endl;
                syscalls.push_back(list[j]);
            }
            else if(!vis[list[j].first])
            {
                q.push(list[j].first);
                vis[list[j].first] = 1;
            }
        }
    }
    return syscalls;
}

int main(int argc, char* argv[])
{
    if(argc != 3)
    {
        cout<<"Usage : ./monitor binary_name start_node"<<endl;
        return 0;
    }

    pid_t cid;
    long eax,rax,rip;
    int insyscall = 0;
    int status;
    int count = 0;
    map<string,int> vis;

    string tempr(argv[1]);
    string main_node(argv[2]);

    tempr = "./"+tempr;
    const char* filename = tempr.c_str();

    map<string,vector<pair<string,string>>> graph = makegraph("automaton");
    vector<pair<string,string>> syscalls = traversegraph(main_node,vis,graph);

   cid = fork();

    if(cid == 0)
    {
        ptrace(PTRACE_TRACEME,0,NULL,NULL);
        execv(filename,NULL);
    }
    else
    {
        while(1)
        {
            wait(&status);
            if(WIFEXITED(status))
                    break;
            
            map<string,int> record;
            vector<pair<string,string>> possible_syscalls;
            int flag = 0;
            for(int i = 0; i<syscalls.size(); i++)
            {
                // check syscall process making is in list
                if(!record[syscalls[i].first])
                {
                    possible_syscalls.push_back(syscalls[i]);
                    //cout<<syscalls[i].first<<" "<<syscalls[i].second<<endl;
                }
                record[syscalls[i].first] = 1;
            }
            
            eax = ptrace(PTRACE_PEEKUSER,cid,8*ORIG_RAX,NULL);
            rax = ptrace(PTRACE_PEEKUSER,cid,8*RAX,NULL);
            string proc_syscall;
            if(rax == -38) count++;
            if(rax == -38 && count > 14)
            {
                rip = ptrace(PTRACE_PEEKUSER,cid,8*RIP,NULL);
                cout<<"Possible syscalls are : "<<endl;
                for(auto i:possible_syscalls)
                    cout<<"=====>"<<i.first<<" "<<i.second<<endl;
                cout<<"\nchild made a system call "<<syscalls_list[eax]<<endl;
                cout<<"========================================================================================================="<<endl;
                proc_syscall = syscalls_list[eax];
                syscalls.clear();
            }
            else
            {
                rip = ptrace(PTRACE_PEEKUSER,cid,8*RIP,NULL);
                flag = 1;
                possible_syscalls.clear();
            }
            for(int i = 0; i<possible_syscalls.size(); i++)
            {
                if(possible_syscalls[i].second == proc_syscall)
                {   vis.clear();
                    vector<pair<string,string>> temp = traversegraph(possible_syscalls[i].first,vis,graph);
                    syscalls.insert(syscalls.end(),temp.begin(),temp.end());
                    flag = 1;
                }
            }
            if(flag == 0)
            {
                cout<<"\nsuspicious system call detected !!!!\nAborting the program...\n";
                cout<<"+++Report+++\n Process was trying to make syscall "<<proc_syscall<<"\n It is not allowed under current to syscall policy\n";
                kill(cid,SIGKILL);
                return 0;
            }
            ptrace(PTRACE_SYSCALL,cid,NULL,NULL);
        }
    }
    return 0;
}