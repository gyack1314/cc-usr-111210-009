"""显示清单身份和原始来源概况。"""
import argparse,json
from pathlib import Path
from .io import load
from .domain import summarize,collect

def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['inspect','collect']);p.add_argument('file');a=p.parse_args()
    v,digest=load(a.file)
    if a.command=='inspect':out={'source_sha256':digest,'summary':summarize(v,Path(a.file).parent)}
    else:out={'source_sha256':digest,'collect':collect(v,Path(a.file).parent)}
    print(json.dumps(out,ensure_ascii=False,indent=2,allow_nan=False))
if __name__=='__main__':main()
