/*---------------------------------------------------------------------------------------------
 *  Copyright (c) 2025 Huawei Technologies Co., Ltd. All rights reserved.
 *  This file is a part of the ModelEngine Project.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

package modelengine.fit.jober.aipp.repository.impl;

import modelengine.fit.jober.aipp.dto.aipplog.AippLogCreateDto;
import modelengine.fit.jober.aipp.entity.AippInstLog;
import modelengine.fit.jober.aipp.mapper.AippLogMapper;
import modelengine.fit.jober.aipp.repository.AippInstanceLogRepository;
import modelengine.fit.jober.aipp.service.DatabaseBaseTest;
import modelengine.fitframework.annotation.Fit;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

/**
 * {@link AippInstanceLogRepositoryImpl}对应测试类。
 *
 * @author 杨祥宇
 * @since 2025-04-10
 */
public class AippInstanceLogRepositoryImplTest extends DatabaseBaseTest {
    @Fit
    private final AippLogMapper mapper = sqlSessionManager.openSession(true).getMapper(AippLogMapper.class);

    private AippInstanceLogRepository repo;

    @BeforeEach
    void setUp() {
        this.repo = new AippInstanceLogRepositoryImpl(mapper);
    }

    @Test
    @DisplayName("测试成功刪除调试信息")
    void testForceDeleteInstanceLogsSuccess() {
        AippLogCreateDto dto = AippLogCreateDto.builder()
                .logId("1")
                .aippId("1")
                .aippType("PREVIEW")
                .instanceId("1")
                .logData("{}")
                .logType("QUESTION")
                .createUserAccount("yyy")
                .build();
        mapper.insertOne(dto);

        repo.forceDeleteInstanceLogs(Collections.singletonList(1L));

        List<Long> expirePreviewInstanceLogs = repo.getExpireInstanceLogIds(dto.getAippType(), 0, 1);

        Assertions.assertEquals(0, expirePreviewInstanceLogs.size());
    }

    @Test
    @DisplayName("测试成功获取过期调试信息")
    void testGetExpiredPreviewInstanceLogsSuccess() {
        AippLogCreateDto dto = AippLogCreateDto.builder()
                .aippId("2")
                .aippType("PREVIEW")
                .instanceId("2")
                .logData("{}")
                .logType("QUESTION")
                .createUserAccount("yyy")
                .build();
        mapper.insertOne(dto);

        List<Long> expirePreviewInstanceLogs = repo.getExpireInstanceLogIds(dto.getAippType(), 0, 1);

        Assertions.assertEquals(1, expirePreviewInstanceLogs.size());
    }

    @Test
    @DisplayName("测试根据对话id成功查询对话详细信息")
    void testSelectByLogIdSuccess() {
        AippLogCreateDto dto = AippLogCreateDto.builder()
                .logId("3")
                .aippId("3")
                .aippType("PREVIEW")
                .instanceId("3")
                .logData("{}")
                .logType("QUESTION")
                .createUserAccount("yyy")
                .build();
        mapper.insertOne(dto);

        List<AippInstLog> aippInstLogs = repo.selectByLogIds(Collections.singletonList(3L));

        Assertions.assertEquals(1, aippInstLogs.size());
        Assertions.assertEquals("3", aippInstLogs.get(0).getInstanceId());
    }
}