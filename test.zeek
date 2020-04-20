#in every 10 mins

#record the number of 404 base one the key of ip            if > 2

#record the total number of http-request also

#record the name and the number of the url about the 404 

#calculate the 404/all request                              if > 0.2

#calculate the most 404 url/404                             if > 0.5

#out put the ip if all the rules are matched                x.x.x.x is a scanner with ...







event zeek_init()

    {

    local r1 = SumStats::Reducer($stream="all reply num", $apply=set(SumStats::SUM));

    #local r2 = SumStats::Reducer($stream="all reply host num", $apply=set(SumStats::UNIQUE));

    local r3 = SumStats::Reducer($stream="404 reply num", $apply=set(SumStats::SUM));

    local r4 = SumStats::Reducer($stream="404 reply host unique", $apply=set(SumStats::UNIQUE));

    SumStats::create([$name="sumstate of scanner",

                      $epoch=10min,

                      $reducers=set(r1,r3,r4),

                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =

                        {

                        local numof404 = result["404 reply num"];

                        local allreply = result["all reply num"];

                        local numof404unique = result["404 reply host unique"];

                        if ( numof404$num > 2 )

                        {

                            if ( numof404$num >allreply$num*0.2 )

                            {

                                

                                if ( numof404unique$unique > numof404$num*0.5 )

                                {

                                    print fmt("%s is a scanner with %s scan attemps on %s urls",key$host,numof404$num,numof404unique$unique);

                                }

                            }

                        }

                        

                        }]);

    }



event http_reply(c: connection, version: string, code: count, reason: string)

    {

    	local st1 = c$http$host;

    	local st2 = c$http$uri;

    	local st3 = st1 + st2;

    	#print st3;

        SumStats::observe("all reply num",SumStats::Key($host=c$id$orig_h),SumStats::Observation($num=1));

        #SumStats::observe("all reply host num",SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=st3));

        if ( code == 404 )

        {

        

        SumStats::observe("404 reply num", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));

        SumStats::observe("404 reply host unique",SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=st3));

        }

    }
