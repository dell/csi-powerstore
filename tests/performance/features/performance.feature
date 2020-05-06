Feature: PowerStore CSI parallel performance
  As a consumer of the CSI interface
  I want to run performance tests
  So that I can get performance statistic

  @current
  Scenario Outline: Performance test to create volumes, publish, node stage, node publish, node unpublish, node unstage, unpublish, delete volumes in parallel
    Given a PowerStore service
    When I create <numberOfVolumes> volumes in parallel
    And there are no errors
    And I publish <numberOfVolumes> volumes in parallel
    And there are no errors
    And I node stage <numberOfVolumes> volumes in parallel
    And there are no errors
    And I node publish <numberOfVolumes> volumes in parallel
    And there are no errors
    And I node unpublish <numberOfVolumes> volumes in parallel
    And there are no errors
    And I node unstage <numberOfVolumes> volumes in parallel
    And there are no errors
    And I unpublish <numberOfVolumes> volumes in parallel
    And there are no errors
    And when I delete <numberOfVolumes> volumes in parallel
    Then there are no errors

    Examples:
      | numberOfVolumes |
      | 2               |
      | 8               |
      | 16              |
      | 32              |
      | 64              |
      | 128             |
      | 256             |
      
